"""
RANSOMRUN Defense Monitor Service
==================================
Blue Team defense tools for ransomware detection:
1. Canary Files (Honeypots) - Detect file access/modification
2. Entropy Monitoring - Detect encryption via Shannon entropy analysis

Integrated with RansomRun's detection engine and alert system.
"""

import os
import math
import time
import json
import threading
import collections
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Callable

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_CANARY_FILES = [
    "passwords.xlsx",
    "financials_2025.pdf", 
    "ceo_login.txt",
    "hr_salaries.csv",
    "confidential_memo.docx"
]

ENTROPY_THRESHOLD = 7.0  # Shannon entropy above this indicates encryption
CANARY_CONTENT = "CONFIDENTIAL DATA - DO NOT ACCESS\n" * 100


# =============================================================================
# ENTROPY CALCULATOR
# =============================================================================

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon Entropy in bits per byte (0.0 - 8.0).
    
    - Normal text files: ~3-5 bits
    - Compressed/encrypted files: ~7.5-8.0 bits
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    counter = collections.Counter(data)
    length = len(data)
    
    for count in counter.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    
    return entropy


def get_file_entropy(filepath: str, max_bytes: int = 65536) -> float:
    """Calculate entropy of a single file (first max_bytes)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(max_bytes)
        return calculate_shannon_entropy(data)
    except Exception:
        return 0.0


def get_folder_entropy(folder_path: str) -> Dict:
    """
    Scan a folder and return entropy statistics.
    
    Returns:
        {
            "average_entropy": float,
            "max_entropy": float,
            "file_count": int,
            "high_entropy_files": [{"path": str, "entropy": float}],
            "is_encrypted": bool
        }
    """
    if not os.path.exists(folder_path):
        return {
            "average_entropy": 0.0,
            "max_entropy": 0.0,
            "file_count": 0,
            "high_entropy_files": [],
            "is_encrypted": False
        }
    
    entropies = []
    high_entropy_files = []
    
    try:
        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    entropy = get_file_entropy(filepath)
                    entropies.append(entropy)
                    
                    if entropy > ENTROPY_THRESHOLD:
                        high_entropy_files.append({
                            "path": filepath,
                            "entropy": round(entropy, 2)
                        })
                except Exception:
                    pass
    except Exception:
        pass
    
    if not entropies:
        return {
            "average_entropy": 0.0,
            "max_entropy": 0.0,
            "file_count": 0,
            "high_entropy_files": [],
            "is_encrypted": False
        }
    
    avg_entropy = sum(entropies) / len(entropies)
    max_entropy = max(entropies)
    
    return {
        "average_entropy": round(avg_entropy, 2),
        "max_entropy": round(max_entropy, 2),
        "file_count": len(entropies),
        "high_entropy_files": high_entropy_files[:10],  # Limit to 10
        "is_encrypted": avg_entropy > ENTROPY_THRESHOLD
    }


# =============================================================================
# CANARY FILE HANDLER
# =============================================================================

class CanaryFileHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """
    Monitors canary (honeypot) files for access/modification.
    Triggers alerts when ransomware touches these files.
    """
    
    def __init__(self, canary_files: List[str], alert_callback: Optional[Callable] = None):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self.canary_files = set(canary_files)
        self.alert_callback = alert_callback
        self.alerts: List[Dict] = []
    
    def on_modified(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if filename in self.canary_files:
                self._trigger_alert(filename, event.src_path, "MODIFIED")
    
    def on_deleted(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if filename in self.canary_files:
                self._trigger_alert(filename, event.src_path, "DELETED")
    
    def on_moved(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if filename in self.canary_files:
                self._trigger_alert(filename, event.src_path, "RENAMED/MOVED")
    
    def _trigger_alert(self, filename: str, filepath: str, action: str):
        """Trigger a canary alert."""
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "CANARY_TRIGGERED",
            "severity": "CRITICAL",
            "filename": filename,
            "filepath": filepath,
            "action": action,
            "message": f"Ransomware activity detected! Canary file '{filename}' was {action}"
        }
        
        self.alerts.append(alert)
        
        # Call external alert callback if provided
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception:
                pass
        
        # Print to console
        print("\n" + "!" * 60)
        print("🚨 CANARY ALERT - RANSOMWARE ACTIVITY DETECTED 🚨")
        print(f"   File: {filename}")
        print(f"   Action: {action}")
        print(f"   Time: {alert['timestamp']}")
        print("!" * 60 + "\n")


# =============================================================================
# CANARY DEFENSE SERVICE
# =============================================================================

class CanaryDefenseService:
    """
    Manages canary file deployment and monitoring.
    """
    
    def __init__(self, target_dir: str, canary_files: List[str] = None):
        self.target_dir = target_dir
        self.canary_files = canary_files or DEFAULT_CANARY_FILES
        self.observer = None
        self.handler = None
        self.is_running = False
    
    def plant_canaries(self) -> Dict:
        """Create honeypot files in the target directory."""
        if not os.path.exists(self.target_dir):
            os.makedirs(self.target_dir, exist_ok=True)
        
        planted = []
        for filename in self.canary_files:
            filepath = os.path.join(self.target_dir, filename)
            try:
                if not os.path.exists(filepath):
                    with open(filepath, "w") as f:
                        f.write(CANARY_CONTENT)
                    
                    # Try to hide the file (Windows)
                    try:
                        import subprocess
                        subprocess.run(["attrib", "+h", filepath], 
                                      capture_output=True, check=False)
                    except Exception:
                        pass
                    
                    planted.append(filename)
            except Exception as e:
                print(f"Failed to plant canary {filename}: {e}")
        
        return {
            "target_dir": self.target_dir,
            "planted": planted,
            "total_canaries": len(self.canary_files)
        }
    
    def start_monitoring(self, alert_callback: Optional[Callable] = None) -> bool:
        """Start monitoring canary files for changes."""
        if not WATCHDOG_AVAILABLE:
            print("Warning: watchdog not installed. Canary monitoring disabled.")
            return False
        
        if self.is_running:
            return True
        
        self.handler = CanaryFileHandler(self.canary_files, alert_callback)
        self.observer = Observer()
        self.observer.schedule(self.handler, path=self.target_dir, recursive=True)
        
        try:
            self.observer.start()
            self.is_running = True
            print(f"[CANARY] Monitoring {len(self.canary_files)} honeypots in '{self.target_dir}'")
            return True
        except Exception as e:
            print(f"[CANARY] Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop monitoring canary files."""
        if self.observer and self.is_running:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.is_running = False
            print("[CANARY] Monitoring stopped")
    
    def get_alerts(self) -> List[Dict]:
        """Get all canary alerts."""
        if self.handler:
            return self.handler.alerts
        return []
    
    def get_status(self) -> Dict:
        """Get current canary defense status."""
        return {
            "is_running": self.is_running,
            "target_dir": self.target_dir,
            "canary_files": self.canary_files,
            "alerts_count": len(self.get_alerts()),
            "watchdog_available": WATCHDOG_AVAILABLE
        }


# =============================================================================
# ENTROPY MONITOR SERVICE
# =============================================================================

class EntropyMonitorService:
    """
    Real-time entropy monitoring service.
    Detects encryption by tracking file entropy changes.
    """
    
    def __init__(self, target_dir: str, check_interval: float = 2.0):
        self.target_dir = target_dir
        self.check_interval = check_interval
        self.history: List[Dict] = []
        self.is_running = False
        self._thread = None
        self._stop_event = threading.Event()
        self.alert_callback = None
        self.encryption_detected = False
    
    def start_monitoring(self, alert_callback: Optional[Callable] = None):
        """Start entropy monitoring in background thread."""
        if self.is_running:
            return
        
        self.alert_callback = alert_callback
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.is_running = True
        print(f"[ENTROPY] Monitoring started for '{self.target_dir}'")
    
    def stop_monitoring(self):
        """Stop entropy monitoring."""
        if self.is_running:
            self._stop_event.set()
            if self._thread:
                self._thread.join(timeout=5)
            self.is_running = False
            print("[ENTROPY] Monitoring stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while not self._stop_event.is_set():
            try:
                result = get_folder_entropy(self.target_dir)
                result["timestamp"] = datetime.utcnow().isoformat()
                
                self.history.append(result)
                
                # Keep only last 100 readings
                if len(self.history) > 100:
                    self.history.pop(0)
                
                # Check for encryption
                if result["is_encrypted"] and not self.encryption_detected:
                    self.encryption_detected = True
                    self._trigger_alert(result)
                elif not result["is_encrypted"]:
                    self.encryption_detected = False
                    
            except Exception as e:
                print(f"[ENTROPY] Monitor error: {e}")
            
            self._stop_event.wait(self.check_interval)
    
    def _trigger_alert(self, result: Dict):
        """Trigger entropy alert."""
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "HIGH_ENTROPY_DETECTED",
            "severity": "CRITICAL",
            "average_entropy": result["average_entropy"],
            "max_entropy": result["max_entropy"],
            "file_count": result["file_count"],
            "message": f"Encryption detected! Average entropy: {result['average_entropy']:.2f} bits"
        }
        
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception:
                pass
        
        print("\n" + "=" * 60)
        print("⚠️  HIGH ENTROPY ALERT - ENCRYPTION DETECTED ⚠️")
        print(f"   Average Entropy: {result['average_entropy']:.2f} bits")
        print(f"   Threshold: {ENTROPY_THRESHOLD} bits")
        print(f"   Files Affected: {result['file_count']}")
        print("=" * 60 + "\n")
    
    def get_current_entropy(self) -> Dict:
        """Get current entropy reading."""
        return get_folder_entropy(self.target_dir)
    
    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get entropy history."""
        return self.history[-limit:]
    
    def get_status(self) -> Dict:
        """Get monitor status."""
        current = self.get_current_entropy() if os.path.exists(self.target_dir) else {}
        return {
            "is_running": self.is_running,
            "target_dir": self.target_dir,
            "check_interval": self.check_interval,
            "history_count": len(self.history),
            "encryption_detected": self.encryption_detected,
            "current_entropy": current.get("average_entropy", 0),
            "threshold": ENTROPY_THRESHOLD
        }


# =============================================================================
# UNIFIED DEFENSE MANAGER
# =============================================================================

class DefenseManager:
    """
    Unified manager for all Blue Team defense tools.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.canary_service: Optional[CanaryDefenseService] = None
        self.entropy_service: Optional[EntropyMonitorService] = None
        self.alerts: List[Dict] = []
        self._initialized = True
    
    def initialize(self, target_dir: str, canary_files: List[str] = None):
        """Initialize defense services."""
        self.canary_service = CanaryDefenseService(target_dir, canary_files)
        self.entropy_service = EntropyMonitorService(target_dir)
    
    def _alert_callback(self, alert: Dict):
        """Unified alert handler."""
        self.alerts.append(alert)
        # Could integrate with RansomRun's alert system here
    
    def deploy_canaries(self) -> Dict:
        """Deploy canary files."""
        if not self.canary_service:
            return {"error": "Canary service not initialized"}
        return self.canary_service.plant_canaries()
    
    def start_all_monitoring(self):
        """Start all defense monitoring."""
        results = {}
        
        if self.canary_service:
            results["canary"] = self.canary_service.start_monitoring(self._alert_callback)
        
        if self.entropy_service:
            self.entropy_service.start_monitoring(self._alert_callback)
            results["entropy"] = True
        
        return results
    
    def stop_all_monitoring(self):
        """Stop all defense monitoring."""
        if self.canary_service:
            self.canary_service.stop_monitoring()
        if self.entropy_service:
            self.entropy_service.stop_monitoring()
    
    def get_full_status(self) -> Dict:
        """Get status of all defense systems."""
        return {
            "canary": self.canary_service.get_status() if self.canary_service else None,
            "entropy": self.entropy_service.get_status() if self.entropy_service else None,
            "total_alerts": len(self.alerts),
            "recent_alerts": self.alerts[-10:]
        }
    
    def get_all_alerts(self) -> List[Dict]:
        """Get all alerts from all services."""
        all_alerts = list(self.alerts)
        if self.canary_service:
            all_alerts.extend(self.canary_service.get_alerts())
        return sorted(all_alerts, key=lambda x: x.get("timestamp", ""), reverse=True)


# Singleton instance
defense_manager = DefenseManager()


# =============================================================================
# STANDALONE USAGE
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RansomRun Defense Monitor")
    parser.add_argument("--target", default="C:\\RansomTest", help="Target directory to monitor")
    parser.add_argument("--mode", choices=["canary", "entropy", "both"], default="both")
    args = parser.parse_args()
    
    print("=" * 60)
    print("  RANSOMRUN BLUE TEAM DEFENSE MONITOR")
    print("=" * 60)
    
    defense_manager.initialize(args.target)
    
    if args.mode in ["canary", "both"]:
        print("\n[*] Deploying canary files...")
        result = defense_manager.deploy_canaries()
        print(f"    Planted: {result.get('planted', [])}")
    
    print(f"\n[*] Starting monitoring on: {args.target}")
    defense_manager.start_all_monitoring()
    
    print("\n[*] Press Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        defense_manager.stop_all_monitoring()
        print("[*] Done.")
