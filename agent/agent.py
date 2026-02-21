"""
RANSOMRUN Windows Agent - Advanced Scenario Engine
===================================================
This agent runs on Windows victim machines and:
1. Registers with the RANSOMRUN backend
2. Polls for tasks
3. Executes simulation scenarios based on JSON config
4. Collects forensic data (files, IOCs, metrics)
5. Reports detailed results back

IMPORTANT: This is for LAB/EDUCATIONAL use only!
Only run on isolated test machines.

SUPPORTED PLAYBOOKS & SCENARIOS:
================================

1. CRYPTO_BASIC - Basic file encryption simulation
   - File renaming with .locked extension
   - Ransom note creation
   - Basic MITRE T1486 (Data Encrypted for Impact)

2. CRYPTO_ADVANCED - Advanced ransomware with persistence
   - All CRYPTO_BASIC features
   - VSS deletion (T1490 - Inhibit System Recovery)
   - Persistence simulation (T1547 - Boot/Logon Autostart)
   - Network beacon (T1071 - Application Layer Protocol)

3. WIPER - Destructive wiper simulation
   - File quarantine (moves files instead of encrypting)
   - No ransom note (pure destruction)
   - VSS deletion
   - T1485 (Data Destruction)

4. EXFILTRATION - Data theft focused
   - File staging and compression
   - Simulated exfiltration preparation
   - T1560 (Archive Collected Data)
   - T1041 (Exfiltration Over C2 Channel)

5. LATERAL_MOVEMENT - Network propagation simulation
   - Network discovery (T1046)
   - Lateral movement tracers (T1021)
   - File drops in shared locations

6. CLOUD_ATTACK - Cloud storage targeting
   - Simulated S3/Azure blob attacks
   - Cloud file encryption (T1530, T1485)
   - Multi-cloud targeting

7. POLYMORPHIC - Evasion-focused attack
   - Hash mutation (T1027 - Obfuscated Files)
   - Code polymorphism simulation
   - Anti-analysis techniques

8. APT_FULL_CHAIN - Complete APT kill chain
   - All techniques combined
   - Persistence + Lateral + Exfil + Encryption
   - Maximum MITRE coverage

NEW PLAYBOOKS (Enhanced for SIEM Dashboard):
============================================

9. CREDENTIAL_DUMP - Credential access simulation
   - LSASS memory dump simulation (T1003.001)
   - SAM database access (T1003.002)
   - Credential file harvesting (T1552)

10. REGISTRY_PERSISTENCE - Registry manipulation
    - Run key persistence (T1547.001)
    - Service creation (T1543.003)
    - Scheduled task creation (T1053.005)

11. PROCESS_INJECTION - Code injection simulation
    - Process hollowing indicators (T1055.012)
    - DLL injection markers (T1055.001)
    - Reflective loading (T1620)

12. DEFENSE_EVASION - Anti-detection techniques
    - Timestomping simulation (T1070.006)
    - Log clearing (T1070.001)
    - Disable security tools (T1562.001)
"""


import os
import sys
import time
import json
import socket
import random
import shutil
import zipfile
import platform
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional, Union

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed.")
    print("Run: pip install requests")
    sys.exit(1)


# =============================================================================
# CONFIGURATION - MODIFY THESE VALUES
# =============================================================================

# Backend server URL (change to your server's IP)
# Can also be set via environment variable: RANSOMRUN_BACKEND_URL
# Example: set RANSOMRUN_BACKEND_URL=http://192.168.10.100:8000
# Use localhost if running backend on same machine: http://127.0.0.1:8000
BACKEND_URL = os.environ.get("RANSOMRUN_BACKEND_URL", "http://192.168.10.55:8000")

# Agent ID - leave empty to use hostname
AGENT_ID = os.environ.get("RANSOMRUN_AGENT_ID", "")

# Polling interval in seconds
POLL_INTERVAL = int(os.environ.get("RANSOMRUN_POLL_INTERVAL", "10"))

# Test directory for ransomware simulation
TEST_DIR = r"C:\RansomTest"

# Log file path
LOG_FILE = r"C:\RansomTest\agent.log"

# Quarantine directory for wiper simulation
QUARANTINE_DIR = r"C:\RansomTest\Quarantine"

# Exfil staging directory
EXFIL_STAGING_DIR = r"C:\RansomTest\ExfilStaging"


# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging():
    """Configure logging to file and console."""
    # Ensure log directory exists
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("RansomRunAgent")


# =============================================================================
# AGENT CLASS
# =============================================================================

class RansomRunAgent:
    """RANSOMRUN Windows Agent."""
    
    def __init__(self, backend_url: str, agent_id: str = None):
        self.backend_url = backend_url.rstrip('/')
        self.hostname = platform.node()
        self.agent_id = agent_id or self.hostname
        self.ip_address = self._get_ip_address()
        self.logger = setup_logging()
        
        self.logger.info("=" * 50)
        self.logger.info("  RANSOMRUN Agent Starting")
        self.logger.info("=" * 50)
        self.logger.info(f"Hostname: {self.hostname}")
        self.logger.info(f"Agent ID: {self.agent_id}")
        self.logger.info(f"IP Address: {self.ip_address}")
        self.logger.info(f"Backend URL: {self.backend_url}")
        self.logger.info(f"Test Directory: {TEST_DIR}")
    
    def _get_ip_address(self) -> str:
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def register(self) -> bool:
        """Register or update agent with backend."""
        try:
            response = requests.post(
                f"{self.backend_url}/api/agent/register",
                json={
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "ip_address": self.ip_address
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.logger.info(f"Registered successfully. Host ID: {data.get('id')}")
                return True
            else:
                self.logger.error(f"Registration failed: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Registration error: {e}")
            return False
    
    def poll_for_task(self) -> dict:
        """Poll backend for pending tasks."""
        try:
            response = requests.get(
                f"{self.backend_url}/api/agent/tasks",
                params={"agent_id": self.agent_id},
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.warning(f"Task poll failed: {response.status_code}")
                return {"task_id": None}
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Task poll error: {e}")
            return {"task_id": None}
    
    def report_result(self, task_id: int, status: str, result_message: str):
        """Report task result back to backend."""
        try:
            response = requests.post(
                f"{self.backend_url}/api/agent/task-result",
                json={
                    "task_id": task_id,
                    "status": status,
                    "result_message": result_message
                },
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info(f"Result reported for task {task_id}: {status}")
            else:
                self.logger.error(f"Result report failed: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Result report error: {e}")
    
    def execute_task(self, task: dict):
        """Execute a task based on its type."""
        task_id = task.get("task_id")
        task_type = task.get("type")
        parameters = task.get("parameters", {})
        
        self.logger.info(f"Executing task {task_id}: {task_type}")
        self.logger.info(f"Parameters: {parameters}")
        
        try:
            if task_type == "simulate_ransomware":
                result = self.simulate_ransomware(parameters)
            elif task_type == "stop_simulation":
                result = self.stop_simulation(parameters)
            elif task_type == "response_kill_process":
                result = self.response_kill_process(parameters)
            elif task_type == "response_disable_user":
                result = self.response_disable_user(parameters)
            elif task_type == "response_isolate_host":
                result = self.response_isolate_host(parameters)
            elif task_type == "response_reisolate_host":
                result = self.response_reisolate_host(parameters)
            elif task_type == "response_deisolate_host":
                result = self.response_deisolate_host(parameters)
            elif task_type == "recovery_enable_user":
                result = self.recovery_enable_user(parameters)
            elif task_type == "recovery_restore_files_from_quarantine":
                result = self.recovery_restore_files_from_quarantine(parameters)
            # NEW PLAYBOOK ACTIONS
            elif task_type == "backup_snapshot":
                result = self.backup_snapshot(parameters)
            elif task_type == "restore_backup":
                result = self.restore_backup(parameters)
            elif task_type == "isolate_host":
                result = self.isolate_host(parameters)
            elif task_type == "deisolate_host":
                result = self.deisolate_host(parameters)
            elif task_type == "protect_backup_targets":
                result = self.protect_backup_targets(parameters)
            elif task_type == "collect_triage":
                result = self.collect_triage(parameters)
            elif task_type == "block_ip":
                result = self.block_ip(parameters)
            else:
                result = (False, f"Unknown task type: {task_type}")
            
            status = "completed" if result[0] else "failed"
            self.report_result(task_id, status, result[1])
            
        except Exception as e:
            self.logger.exception(f"Task execution error: {e}")
            self.report_result(task_id, "failed", str(e))
    
    # =========================================================================
    # SIMULATION ACTIONS - ADVANCED SCENARIO ENGINE
    # =========================================================================
    
    def simulate_ransomware(self, parameters: dict) -> tuple:
        """
        Execute ransomware simulation based on scenario config.
        
        The scenario config (JSON) defines:
        - directories_to_target
        - file_extensions
        - rename_pattern
        - ransom_note settings
        - simulate_vssadmin, simulate_persistence, simulate_exfiltration
        - intensity_level
        - optional_delay_seconds
        """
        scenario_key = parameters.get("scenario_key", "crypto_basic")
        scenario_config = parameters.get("scenario_config", {})
        run_id = parameters.get("run_id")
        
        self.logger.info(f"Running scenario: {scenario_key}")
        self.logger.info(f"Config: {json.dumps(scenario_config, indent=2)}")
        
        # Initialize forensic collectors
        self.affected_files: List[Dict] = []
        self.iocs: List[Dict] = []
        self.events: List[Dict] = []
        self.metrics: Dict[str, float] = {}
        
        start_time = datetime.utcnow()
        results = []
        
        try:
            # Launch GUI ransomware popup for high-impact scenarios
            gui_enabled = scenario_config.get("enable_gui_popup", False)
            if gui_enabled or scenario_key in ["advanced_polymorphic", "lockbit_sim", "conti_sim", "blackcat_sim"]:
                self.logger.info("Launching GUI ransomware popup...")
                self._launch_gui_ransomware()
                results.append("GUI ransomware popup launched")
            # Apply optional delay (dwell time simulation)
            delay = scenario_config.get("optional_delay_seconds", 0)
            if delay > 0:
                self.logger.info(f"Simulating dwell time: {delay}s delay")
                self._add_event("DWELL_TIME", {"delay_seconds": delay})
                time.sleep(delay)
            
            # Get target directories
            directories = scenario_config.get("directories_to_target", [TEST_DIR])
            if not directories:
                directories = [TEST_DIR]
            
            # Ensure directories exist and create sample files
            for dir_path in directories:
                self._ensure_test_directory(dir_path)
            
            results.append(f"Prepared {len(directories)} target directories")
            
            # Get file extensions to target
            extensions = scenario_config.get("file_extensions", [".txt", ".docx", ".xlsx"])
            rename_pattern = scenario_config.get("rename_pattern", ".locked")
            intensity = scenario_config.get("intensity_level", 2)
            quarantine_mode = scenario_config.get("quarantine_mode", False)
            
            # Stage 1: Persistence (if enabled)
            if scenario_config.get("simulate_persistence", False):
                self._simulate_persistence()
                results.append("Persistence mechanism simulated")
            
            # Stage 2: File operations (rename/quarantine)
            if rename_pattern and extensions:
                file_count = self._process_files(
                    directories, extensions, rename_pattern, 
                    intensity, quarantine_mode
                )
                action = "quarantined" if quarantine_mode else "encrypted"
                results.append(f"{action} {file_count} files")
                self.metrics["files_touched"] = file_count
            else:
                self.metrics["files_touched"] = 0
                results.append("No file operations (scenario config)")
            
            # Stage 3: Ransom note creation
            ransom_config = scenario_config.get("ransom_note", {})
            if ransom_config:
                note_count = self._create_ransom_notes(directories, ransom_config)
                results.append(f"Created {note_count} ransom notes")
            
            # Stage 4: Shadow copy deletion
            if scenario_config.get("simulate_vssadmin", False):
                vss_result = self._delete_shadow_copies()
                results.append(vss_result)
            
            # Stage 5: Exfiltration preparation
            if scenario_config.get("simulate_exfiltration", False):
                exfil_result = self._simulate_exfiltration(directories, extensions)
                results.append(exfil_result)
            
            # Stage 6: Network beacon simulation
            if scenario_config.get("simulate_network_beacon", False):
                self._simulate_network_beacon()
                results.append("Network beacon simulated")
            
            # Stage 7: Lateral movement simulation (Advanced)
            if scenario_config.get("simulate_lateral_movement", False):
                lateral_result = self._simulate_lateral_movement()
                results.append(lateral_result)
            
            # Stage 8: Cloud attack simulation (Advanced)
            if scenario_config.get("simulate_cloud_attack", False):
                cloud_result = self._simulate_cloud_attack()
                results.append(cloud_result)
            
            # Stage 9: Polymorphic mode logging (Advanced)
            if scenario_config.get("polymorphic_mode", False):
                self._log_polymorphic_activity()
                results.append("Polymorphic evasion simulated")
            
            # Stage 10: Credential dumping simulation (NEW)
            if scenario_config.get("simulate_credential_dump", False):
                cred_result = self._simulate_credential_dump()
                results.append(cred_result)
            
            # Stage 11: Registry persistence (NEW)
            if scenario_config.get("simulate_registry_persistence", False):
                reg_result = self._simulate_registry_persistence()
                results.append(reg_result)
            
            # Stage 12: Process injection (NEW)
            if scenario_config.get("simulate_process_injection", False):
                proc_result = self._simulate_process_injection()
                results.append(proc_result)
            
            # Stage 13: Defense evasion (NEW)
            if scenario_config.get("simulate_defense_evasion", False):
                evasion_result = self._simulate_defense_evasion()
                results.append(evasion_result)
            
            # Calculate metrics
            end_time = datetime.utcnow()
            duration_ms = (end_time - start_time).total_seconds() * 1000
            self.metrics["execution_time_ms"] = duration_ms
            self.metrics["alerts_expected"] = self._count_expected_alerts(scenario_config)
            
            summary = "; ".join(results)
            self.logger.info(f"Simulation complete: {summary}")
            
            # Report extended results
            self._report_extended_results(run_id)
            
            return (True, summary)
            
        except Exception as e:
            self.logger.exception("Simulation error")
            return (False, str(e))
    
    def stop_simulation(self, parameters: dict) -> tuple:
        """
        Stop a running simulation.
        
        This is called when the backend sends a stop_simulation task.
        The agent should gracefully halt any ongoing simulation.
        """
        run_id = parameters.get("run_id")
        
        self.logger.warning(f"STOP SIMULATION requested for run_id: {run_id}")
        
        try:
            # Set a stop flag (if we had a running simulation loop, we'd check this)
            # For our current implementation, simulations are atomic tasks that complete quickly
            # So we just acknowledge the stop request
            
            # Log the stop event
            self.logger.info(f"Simulation stop acknowledged for run {run_id}")
            
            # If there were any cleanup actions needed, do them here
            # For example: close open files, release resources, etc.
            
            return (True, f"Simulation stopped successfully for run {run_id}")
            
        except Exception as e:
            self.logger.exception("Stop simulation error")
            return (False, f"Failed to stop simulation: {e}")
    
    def _ensure_test_directory(self, dir_path: str):
        """Ensure test directory exists with sample files."""
        path = Path(dir_path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Create sample files if directory is empty or has few files
        existing_files = list(path.glob("*.*"))
        if len(existing_files) < 5:
            sample_files = [
                ("document1.docx", "Important business document content."),
                ("document2.docx", "Confidential project proposal."),
                ("spreadsheet.xlsx", "Financial data and projections."),
                ("presentation.pptx", "Quarterly review slides."),
                ("notes.txt", "Meeting notes and action items."),
                ("data.csv", "id,name,value\n1,item1,100\n2,item2,200"),
                ("report.pdf", "Annual report summary."),
                ("config.json", '{"setting": "value"}'),
                ("backup.xml", "<data><item>backup</item></data>"),
            ]
            
            for filename, content in sample_files:
                filepath = path / filename
                if not filepath.exists():
                    filepath.write_text(content)
                    self.logger.info(f"Created sample: {filepath}")
    
    def _process_files(
        self, 
        directories: List[str], 
        extensions: List[str], 
        rename_pattern: str,
        intensity: int,
        quarantine_mode: bool
    ) -> int:
        """Process files according to scenario config."""
        processed = 0
        max_files = intensity * 50  # intensity 1=50, 2=100, 3=150, etc.
        
        for dir_path in directories:
            path = Path(dir_path)
            if not path.exists():
                continue
            
            # Get matching files
            files = []
            for ext in extensions:
                files.extend(path.glob(f"*{ext}"))
            
            # Limit based on intensity
            if len(files) > max_files:
                files = random.sample(files, max_files)
            
            for filepath in files:
                if processed >= max_files:
                    break
                
                # Skip special files
                if filepath.name in ["agent.log", "README_RESTORE.txt"]:
                    continue
                if rename_pattern and filepath.name.endswith(rename_pattern):
                    continue
                
                try:
                    if quarantine_mode:
                        # Move to quarantine
                        quarantine_path = Path(QUARANTINE_DIR)
                        quarantine_path.mkdir(parents=True, exist_ok=True)
                        new_path = quarantine_path / filepath.name
                        shutil.move(str(filepath), str(new_path))
                        action_type = "QUARANTINED"
                    else:
                        # Copy file with ransomware extension (triggers Sysmon Event ID 11)
                        # This creates a new file which Sysmon will detect
                        new_path = filepath.with_suffix(filepath.suffix + rename_pattern)
                        shutil.copy2(str(filepath), str(new_path))
                        # Delete original to simulate encryption
                        filepath.unlink()
                        action_type = "ENCRYPTED"
                    
                    self.affected_files.append({
                        "original_path": str(filepath),
                        "new_path": str(new_path),
                        "action_type": action_type
                    })
                    
                    self.iocs.append({
                        "ioc_type": "FILE_PATH",
                        "value": str(new_path),
                        "context": f"ransomware_{action_type.lower()}"
                    })
                    
                    processed += 1
                    self.logger.info(f"{action_type}: {filepath.name}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to process {filepath}: {e}")
        
        self._add_event("FILES_PROCESSED", {"count": processed, "action": "quarantine" if quarantine_mode else "rename"})
        return processed
    
    def _create_ransom_notes(self, directories: List[str], ransom_config: dict) -> int:
        """Create ransom notes in specified locations."""
        filename = ransom_config.get("filename", "README_RESTORE.txt")
        content = ransom_config.get("content", "Your files have been encrypted!")
        locations = ransom_config.get("locations", ["target_root"])
        
        created = 0
        
        for location in locations:
            paths_to_create = []
            
            if location == "target_root":
                # Use directories if available, otherwise use TEST_DIR
                if directories:
                    paths_to_create = [Path(d) for d in directories]
                else:
                    paths_to_create = [Path(TEST_DIR)]
            elif location == "desktop":
                # Get desktop path - try multiple common locations
                desktop = Path.home() / "Desktop"
                if not desktop.exists():
                    desktop = Path.home() / "OneDrive" / "Desktop"
                if not desktop.exists():
                    # Create in TEST_DIR as fallback
                    desktop = Path(TEST_DIR)
                desktop.mkdir(parents=True, exist_ok=True)
                paths_to_create = [desktop]
            else:
                # Treat as literal path
                paths_to_create = [Path(location)]
            
            for path in paths_to_create:
                try:
                    if path.exists():
                        note_path = path / filename
                        note_path.write_text(content)
                        created += 1
                        self.logger.info(f"Created ransom note: {note_path}")
                        
                        self.iocs.append({
                            "ioc_type": "FILE_PATH",
                            "value": str(note_path),
                            "context": "ransom_note"
                        })
                except Exception as e:
                    self.logger.warning(f"Failed to create note at {path}: {e}")
        
        self._add_event("RANSOM_NOTE_CREATED", {"count": created, "filename": filename})
        return created
    
    def _delete_shadow_copies(self) -> str:
        """Delete shadow copies using vssadmin."""
        self.logger.warning("Executing vssadmin shadow copy deletion")
        
        cmd = "vssadmin delete shadows /all /quiet"
        self.iocs.append({
            "ioc_type": "CMD_LINE",
            "value": cmd,
            "context": "shadow_copy_deletion"
        })
        
        try:
            result = subprocess.run(
                ["vssadmin", "delete", "shadows", "/all", "/quiet"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            self._add_event("VSSADMIN_EXECUTED", {
                "command": cmd,
                "return_code": result.returncode,
                "output": result.stdout[:500] if result.stdout else result.stderr[:500]
            })
            
            if result.returncode == 0:
                return "Shadow copies deleted"
            else:
                return f"vssadmin: {result.stderr or 'No shadows or access denied'}"
                
        except subprocess.TimeoutExpired:
            return "vssadmin timed out"
        except Exception as e:
            return f"vssadmin error: {e}"
    
    def _simulate_persistence(self):
        """Simulate persistence mechanism (registry key)."""
        self.logger.info("Simulating persistence mechanism")
        
        # Simulate registry persistence (don't actually create it)
        reg_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        reg_value = "RansomRunSim"
        
        self.iocs.append({
            "ioc_type": "REG_KEY",
            "value": f"{reg_key}\\{reg_value}",
            "context": "persistence_simulation"
        })
        
        self._add_event("PERSISTENCE_CREATED", {
            "type": "registry",
            "key": reg_key,
            "value": reg_value,
            "simulated": True
        })
        
        self.logger.info(f"Persistence simulated: {reg_key}\\{reg_value}")
    
    def _simulate_exfiltration(self, directories: List[str], extensions: List[str]) -> str:
        """Simulate data exfiltration preparation."""
        self.logger.info("Simulating exfiltration preparation")
        
        staging_path = Path(EXFIL_STAGING_DIR)
        staging_path.mkdir(parents=True, exist_ok=True)
        
        # Create a staging ZIP file
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        zip_path = staging_path / f"exfil_staging_{timestamp}.zip"
        
        files_staged = 0
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for dir_path in directories:
                    path = Path(dir_path)
                    if not path.exists():
                        continue
                    
                    for ext in extensions[:3]:  # Limit to first 3 extensions
                        for filepath in list(path.glob(f"*{ext}"))[:10]:  # Max 10 files per ext
                            try:
                                zf.write(filepath, filepath.name)
                                files_staged += 1
                            except:
                                pass
            
            zip_size = zip_path.stat().st_size
            
            self.iocs.append({
                "ioc_type": "FILE_PATH",
                "value": str(zip_path),
                "context": "exfil_staging_archive"
            })
            
            self._add_event("EXFIL_PREPARED", {
                "archive_path": str(zip_path),
                "files_count": files_staged,
                "size_bytes": zip_size
            })
            
            self.metrics["exfil_files_staged"] = files_staged
            self.metrics["exfil_archive_size"] = zip_size
            
            return f"Exfil staged: {files_staged} files ({zip_size} bytes)"
            
        except Exception as e:
            return f"Exfil staging error: {e}"
    
    def _simulate_network_beacon(self):
        """Simulate C2 network beacon (log only, no actual connection)."""
        self.logger.info("Simulating network beacon")
        
        beacon_targets = [
            "malware-c2.evil.local:443",
            "exfil-server.bad.local:8080"
        ]
        
        for target in beacon_targets:
            self.iocs.append({
                "ioc_type": "NETWORK",
                "value": target,
                "context": "c2_beacon_simulation"
            })
        
        self._add_event("NETWORK_BEACON", {
            "targets": beacon_targets,
            "simulated": True
        })
    
    def _simulate_lateral_movement(self) -> str:
        """
        Simulate lateral movement (T1021).
        Attempts to write tracer files to network-accessible locations.
        """
        self.logger.info("[MITRE ATT&CK] T1021: Simulating lateral movement")
        
        # Network discovery (T1046)
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "127.0.0.1"
        
        self._add_event("NETWORK_DISCOVERY", {
            "technique": "T1046",
            "hostname": hostname,
            "ip_address": ip_address
        })
        
        self.iocs.append({
            "ioc_type": "NETWORK",
            "value": f"{hostname}:{ip_address}",
            "context": "network_discovery"
        })
        
        # Attempt to write tracer files to simulate spread
        lateral_targets = [
            "C:\\Users\\Public",
            "C:\\Users\\Public\\Documents",
        ]
        
        success_count = 0
        for target in lateral_targets:
            try:
                target_path = Path(target)
                if target_path.exists():
                    tracer_file = target_path / "LATERAL_MOVEMENT_TRACER.txt"
                    tracer_file.write_text(
                        f"SIMULATION: Lateral movement tracer\n"
                        f"Source: {hostname} ({ip_address})\n"
                        f"Time: {datetime.utcnow().isoformat()}\n"
                        f"This file proves the ransomware could spread to this location.\n"
                    )
                    success_count += 1
                    
                    self.iocs.append({
                        "ioc_type": "FILE_PATH",
                        "value": str(tracer_file),
                        "context": "lateral_movement_tracer"
                    })
                    
                    self.logger.info(f"Lateral movement: wrote tracer to {target}")
            except Exception as e:
                self.logger.debug(f"Lateral movement blocked for {target}: {e}")
        
        self._add_event("LATERAL_MOVEMENT", {
            "technique": "T1021",
            "targets_attempted": len(lateral_targets),
            "targets_successful": success_count,
            "source_host": hostname
        })
        
        return f"Lateral movement: {success_count}/{len(lateral_targets)} targets reached"
    
    def _simulate_cloud_attack(self) -> str:
        """
        Simulate cloud storage attack (T1530, T1485).
        Mocks S3/cloud bucket operations without actual API calls.
        """
        self.logger.info("[MITRE ATT&CK] T1530: Simulating cloud storage attack")
        
        # Simulated cloud targets
        cloud_targets = [
            {"bucket": "company-backups-critical", "provider": "AWS S3"},
            {"bucket": "finance-data-2025", "provider": "AWS S3"},
            {"bucket": "customer-database", "provider": "Azure Blob"}
        ]
        
        # Simulated files in cloud
        cloud_files = [
            "database_dump.sql",
            "ceo_emails.zip", 
            "customer_list.csv",
            "financials_2025.xlsx",
            "employee_records.json"
        ]
        
        self._add_event("CLOUD_DISCOVERY", {
            "technique": "T1530",
            "buckets_found": len(cloud_targets),
            "files_found": len(cloud_files)
        })
        
        # Simulate encryption of cloud files
        encrypted_files = []
        for file in cloud_files:
            encrypted_name = f"{file}.enc"
            encrypted_files.append(encrypted_name)
            
            self.iocs.append({
                "ioc_type": "CLOUD_FILE",
                "value": f"s3://company-backups-critical/{encrypted_name}",
                "context": "cloud_encryption"
            })
            
            self.logger.info(f"Cloud attack: {file} -> {encrypted_name}")
            time.sleep(0.3)  # Simulate processing time
        
        self._add_event("CLOUD_ATTACK", {
            "technique": "T1485",
            "files_encrypted": len(encrypted_files),
            "files_deleted": len(cloud_files),
            "ransom_note_dropped": True,
            "simulated": True
        })
        
        # Log ransom note in cloud
        self.iocs.append({
            "ioc_type": "CLOUD_FILE",
            "value": "s3://company-backups-critical/RESTORE_INSTRUCTIONS.txt",
            "context": "cloud_ransom_note"
        })
        
        self.metrics["cloud_files_encrypted"] = len(encrypted_files)
        self.metrics["cloud_buckets_targeted"] = len(cloud_targets)
        
        return f"Cloud attack: {len(encrypted_files)} files encrypted across {len(cloud_targets)} buckets"
    
    def _log_polymorphic_activity(self):
        """
        Log polymorphic dropper activity (T1027).
        Simulates hash evasion through code mutation.
        """
        self.logger.info("[MITRE ATT&CK] T1027: Polymorphic payload generation")
        
        import hashlib
        import random
        import string
        
        # Generate random "junk code" to simulate polymorphism
        junk_var = ''.join(random.choices(string.ascii_lowercase, k=8))
        junk_value = random.randint(1000, 9999)
        
        # Simulate original and mutated hashes
        original_hash = hashlib.sha256(b"original_payload_content").hexdigest()[:16]
        mutated_hash = hashlib.sha256(f"mutated_{junk_var}_{junk_value}".encode()).hexdigest()[:16]
        
        self._add_event("POLYMORPHIC_MUTATION", {
            "technique": "T1027",
            "original_hash": original_hash,
            "mutated_hash": mutated_hash,
            "junk_variable": junk_var,
            "evasion_type": "hash_mutation"
        })
        
        self.iocs.append({
            "ioc_type": "HASH",
            "value": mutated_hash,
            "context": "polymorphic_payload_hash"
        })
        
        self.logger.info(f"Polymorphic mutation: {original_hash} -> {mutated_hash}")
    
    def _simulate_credential_dump(self) -> str:
        """
        Simulate credential dumping (T1003).
        Logs indicators of LSASS access and SAM database harvesting.
        """
        self.logger.warning("[MITRE ATT&CK] T1003: Credential Dumping Simulation")
        
        # Simulate LSASS memory dump (T1003.001)
        lsass_dump_path = Path(EXFIL_STAGING_DIR) / "lsass_dump.dmp"
        lsass_dump_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create a dummy file to simulate dump
        try:
            lsass_dump_path.write_bytes(b"SIMULATED_LSASS_DUMP" * 100)
            
            self._add_event("LSASS_DUMP", {
                "technique": "T1003.001",
                "target_process": "lsass.exe",
                "dump_path": str(lsass_dump_path),
                "simulated": True
            })
            
            self.iocs.append({
                "ioc_type": "FILE_PATH",
                "value": str(lsass_dump_path),
                "context": "lsass_memory_dump"
            })
            
            self.logger.warning(f"LSASS dump simulated: {lsass_dump_path}")
        except Exception as e:
            self.logger.warning(f"LSASS dump simulation failed: {e}")
        
        # Simulate SAM database access (T1003.002)
        sam_paths = [
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Windows\System32\config\SECURITY"
        ]
        
        for sam_path in sam_paths:
            self.iocs.append({
                "ioc_type": "FILE_PATH",
                "value": sam_path,
                "context": "sam_database_access"
            })
        
        self._add_event("SAM_ACCESS", {
            "technique": "T1003.002",
            "files_accessed": sam_paths,
            "simulated": True
        })
        
        # Simulate credential file harvesting (T1552)
        cred_files = [
            "browser_passwords.txt",
            "wifi_credentials.txt",
            "saved_passwords.db"
        ]
        
        staging_path = Path(EXFIL_STAGING_DIR)
        for cred_file in cred_files:
            try:
                file_path = staging_path / cred_file
                file_path.write_text(f"SIMULATED CREDENTIALS: {cred_file}")
                
                self.iocs.append({
                    "ioc_type": "FILE_PATH",
                    "value": str(file_path),
                    "context": "credential_harvesting"
                })
            except:
                pass
        
        self._add_event("CREDENTIAL_HARVEST", {
            "technique": "T1552",
            "files_harvested": len(cred_files),
            "simulated": True
        })
        
        self.metrics["credentials_dumped"] = len(sam_paths) + len(cred_files)
        
        return f"Credential dump: LSASS + SAM + {len(cred_files)} credential files"
    
    def _simulate_registry_persistence(self) -> str:
        """
        Simulate registry-based persistence mechanisms (T1547).
        Logs registry modifications without actually creating them.
        """
        self.logger.warning("[MITRE ATT&CK] T1547: Registry Persistence Simulation")
        
        # Run key persistence (T1547.001)
        run_keys = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefender",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\SystemCheck"
        ]
        
        for reg_key in run_keys:
            self.iocs.append({
                "ioc_type": "REG_KEY",
                "value": reg_key,
                "context": "run_key_persistence"
            })
        
        self._add_event("REGISTRY_PERSISTENCE", {
            "technique": "T1547.001",
            "keys_modified": run_keys,
            "simulated": True
        })
        
        # Service creation simulation (T1543.003)
        service_name = "WindowsSecurityService"
        service_path = r"C:\Windows\System32\svchost_update.exe"
        
        self.iocs.append({
            "ioc_type": "SERVICE",
            "value": service_name,
            "context": "malicious_service_creation"
        })
        
        self._add_event("SERVICE_CREATION", {
            "technique": "T1543.003",
            "service_name": service_name,
            "binary_path": service_path,
            "simulated": True
        })
        
        # Scheduled task simulation (T1053.005)
        task_name = "SystemMaintenanceTask"
        task_command = r"C:\Windows\Temp\update.exe"
        
        self.iocs.append({
            "ioc_type": "SCHEDULED_TASK",
            "value": task_name,
            "context": "persistence_scheduled_task"
        })
        
        self._add_event("SCHEDULED_TASK", {
            "technique": "T1053.005",
            "task_name": task_name,
            "command": task_command,
            "trigger": "daily",
            "simulated": True
        })
        
        self.metrics["persistence_mechanisms"] = len(run_keys) + 2
        
        return f"Registry persistence: {len(run_keys)} run keys + service + scheduled task"
    
    def _simulate_process_injection(self) -> str:
        """
        Simulate process injection techniques (T1055).
        Logs indicators without actual injection.
        """
        self.logger.warning("[MITRE ATT&CK] T1055: Process Injection Simulation")
        
        # Process hollowing simulation (T1055.012)
        target_processes = [
            "svchost.exe",
            "explorer.exe",
            "notepad.exe"
        ]
        
        for proc in target_processes:
            self.iocs.append({
                "ioc_type": "PROCESS",
                "value": proc,
                "context": "process_hollowing_target"
            })
        
        self._add_event("PROCESS_HOLLOWING", {
            "technique": "T1055.012",
            "target_processes": target_processes,
            "injected_code_size": 65536,
            "simulated": True
        })
        
        # DLL injection simulation (T1055.001)
        malicious_dll = r"C:\Windows\Temp\payload.dll"
        
        self.iocs.append({
            "ioc_type": "FILE_PATH",
            "value": malicious_dll,
            "context": "malicious_dll_injection"
        })
        
        self._add_event("DLL_INJECTION", {
            "technique": "T1055.001",
            "dll_path": malicious_dll,
            "target_process": "explorer.exe",
            "injection_method": "CreateRemoteThread",
            "simulated": True
        })
        
        # Reflective DLL loading (T1620)
        self._add_event("REFLECTIVE_LOADING", {
            "technique": "T1620",
            "module_name": "reflective_loader.dll",
            "in_memory": True,
            "simulated": True
        })
        
        self.metrics["injection_attempts"] = len(target_processes)
        
        return f"Process injection: {len(target_processes)} targets (hollowing + DLL injection)"
    
    def _simulate_defense_evasion(self) -> str:
        """
        Simulate defense evasion techniques (T1070, T1562).
        Logs anti-forensics and security tool tampering.
        """
        self.logger.warning("[MITRE ATT&CK] T1070/T1562: Defense Evasion Simulation")
        
        # Log clearing simulation (T1070.001)
        event_logs = [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational"
        ]
        
        for log in event_logs:
            self.iocs.append({
                "ioc_type": "EVENT_LOG",
                "value": log,
                "context": "log_clearing"
            })
        
        self._add_event("LOG_CLEARING", {
            "technique": "T1070.001",
            "logs_cleared": event_logs,
            "simulated": True
        })
        
        # Timestomping simulation (T1070.006)
        timestomp_files = [
            r"C:\Windows\Temp\malware.exe",
            r"C:\Users\Public\payload.dll"
        ]
        
        for file_path in timestomp_files:
            self.iocs.append({
                "ioc_type": "FILE_PATH",
                "value": file_path,
                "context": "timestomping"
            })
        
        self._add_event("TIMESTOMPING", {
            "technique": "T1070.006",
            "files_modified": timestomp_files,
            "new_timestamp": "2020-01-01 00:00:00",
            "simulated": True
        })
        
        # Disable security tools (T1562.001)
        security_tools = [
            "Windows Defender",
            "Sysmon",
            "Windows Firewall"
        ]
        
        for tool in security_tools:
            self.iocs.append({
                "ioc_type": "SECURITY_TOOL",
                "value": tool,
                "context": "security_tool_tampering"
            })
        
        self._add_event("DISABLE_SECURITY", {
            "technique": "T1562.001",
            "tools_disabled": security_tools,
            "methods": ["service_stop", "registry_modification", "policy_change"],
            "simulated": True
        })
        
        self.metrics["evasion_techniques"] = len(event_logs) + len(security_tools)
        
        return f"Defense evasion: {len(event_logs)} logs cleared + {len(security_tools)} security tools disabled"
    
    def _launch_gui_ransomware(self):
        """Launch GUI ransomware popup in separate process."""
        try:
            # Get path to GUI script
            agent_dir = Path(__file__).parent
            gui_script = agent_dir.parent / "Advanced_Simulation" / "wana_decrypt0r_gui.py"
            
            if not gui_script.exists():
                self.logger.warning(f"GUI script not found: {gui_script}")
                return
            
            # Launch in separate process with new console window
            if platform.system() == "Windows":
                # Windows: Launch with pythonw to avoid console or use CREATE_NEW_CONSOLE
                subprocess.Popen(
                    [sys.executable, str(gui_script)],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=str(gui_script.parent)
                )
            else:
                # Linux/Mac: Launch in background
                subprocess.Popen(
                    [sys.executable, str(gui_script)],
                    cwd=str(gui_script.parent),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            self.logger.info("GUI ransomware popup launched successfully")
            self._add_event("GUI_RANSOMWARE_LAUNCHED", {
                "technique": "T1486",
                "gui_script": str(gui_script),
                "visual_impact": True
            })
            
        except Exception as e:
            self.logger.error(f"Failed to launch GUI ransomware: {e}")
    
    def _add_event(self, event_type: str, details: dict):
        """Add an event to the timeline."""
        self.events.append({
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        })
    
    def _count_expected_alerts(self, config: dict) -> int:
        """Estimate number of alerts this scenario should trigger."""
        count = 0
        if config.get("simulate_vssadmin"):
            count += 1
        if config.get("rename_pattern"):
            count += 1
        if config.get("ransom_note"):
            count += 1
        if config.get("simulate_persistence"):
            count += 1
        if config.get("simulate_exfiltration"):
            count += 1
        if config.get("simulate_lateral_movement"):
            count += 2  # Network discovery + lateral movement
        if config.get("simulate_cloud_attack"):
            count += 2  # Cloud discovery + cloud attack
        if config.get("polymorphic_mode"):
            count += 1
        if config.get("simulate_credential_dump"):
            count += 2  # LSASS + SAM access
        if config.get("simulate_registry_persistence"):
            count += 1
        if config.get("simulate_process_injection"):
            count += 1
        if config.get("simulate_defense_evasion"):
            count += 2  # Log clearing + AV disable
        return count
    
    def _report_extended_results(self, run_id: Optional[int]):
        """Report extended forensic results to backend."""
        if not run_id:
            return
        
        try:
            payload = {
                "run_id": run_id,
                "files_affected": self.affected_files[:100],  # Limit to 100
                "iocs": self.iocs[:50],  # Limit to 50
                "metrics": self.metrics,
                "events": self.events
            }
            
            response = requests.post(
                f"{self.backend_url}/api/siem/agent/extended-result",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Extended results reported successfully")
            else:
                self.logger.warning(f"Extended results report failed: {response.status_code}")
                
        except Exception as e:
            self.logger.warning(f"Failed to report extended results: {e}")
    
    # =========================================================================
    # RESPONSE ACTIONS
    # =========================================================================
    
    def response_kill_process(self, parameters: dict) -> tuple:
        """Kill a specified process."""
        process_name = parameters.get("process_name")
        
        if not process_name:
            return (False, "No process_name specified")
        
        self.logger.info(f"Killing process: {process_name}")
        
        try:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", process_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                msg = f"Successfully killed process: {process_name}"
                self.logger.info(msg)
                return (True, msg)
            else:
                msg = f"taskkill output: {result.stdout or result.stderr}"
                self.logger.warning(msg)
                # Still return success if process wasn't found (already dead)
                if "not found" in msg.lower() or "could not be found" in msg.lower():
                    return (True, f"Process {process_name} not running")
                return (False, msg)
                
        except subprocess.TimeoutExpired:
            return (False, "taskkill timed out")
        except Exception as e:
            return (False, str(e))
    
    def response_disable_user(self, parameters: dict) -> tuple:
        """Disable a Windows user account."""
        username = parameters.get("username")
        
        if not username:
            return (False, "No username specified")
        
        self.logger.info(f"Disabling user: {username}")
        
        try:
            result = subprocess.run(
                ["net", "user", username, "/active:no"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                msg = f"Successfully disabled user: {username}"
                self.logger.info(msg)
                return (True, msg)
            else:
                msg = f"net user output: {result.stdout or result.stderr}"
                self.logger.warning(msg)
                return (False, msg)
                
        except subprocess.TimeoutExpired:
            return (False, "net user timed out")
        except Exception as e:
            return (False, str(e))
    
    def response_isolate_host(self, parameters: dict) -> tuple:
        """
        Isolate the host based on the specified policy.
        
        Policies:
        - FIREWALL_BLOCK: Block all outbound traffic via Windows Firewall
        - DISABLE_NIC: Disable network adapter(s)
        - HYBRID: Both firewall block and disable secondary NICs
        """
        policy = parameters.get("policy", "FIREWALL_BLOCK")
        adapter_name = parameters.get("adapter_name")
        
        self.logger.warning(f"ISOLATING HOST - Policy: {policy}")
        
        results = []
        success = True
        
        try:
            if policy in ["FIREWALL_BLOCK", "HYBRID"]:
                fw_success, fw_msg = self._apply_firewall_isolation()
                results.append(fw_msg)
                if not fw_success:
                    success = False
            
            if policy in ["DISABLE_NIC", "HYBRID"]:
                nic_success, nic_msg = self._disable_network_adapter(adapter_name)
                results.append(nic_msg)
                if not nic_success:
                    success = False
            
            msg = "; ".join(results)
            self.logger.warning(f"Isolation result: {msg}")
            return (success, msg)
            
        except Exception as e:
            self.logger.exception("Isolation error")
            return (False, str(e))
    
    def response_reisolate_host(self, parameters: dict) -> tuple:
        """
        Re-isolate the host by cleaning up old isolation and re-applying.
        Used when isolation may have failed or been partially restored.
        """
        policy = parameters.get("policy", "FIREWALL_BLOCK")
        adapter_name = parameters.get("adapter_name")
        
        self.logger.warning(f"RE-ISOLATING HOST - Policy: {policy}")
        
        results = []
        success = True
        
        try:
            # First, clean up any existing isolation rules
            self.logger.info("Cleaning up existing isolation rules...")
            self._remove_firewall_isolation()
            
            # Re-apply isolation
            if policy in ["FIREWALL_BLOCK", "HYBRID"]:
                fw_success, fw_msg = self._apply_firewall_isolation()
                results.append(f"[RE-ISOLATION] {fw_msg}")
                if not fw_success:
                    success = False
            
            if policy in ["DISABLE_NIC", "HYBRID"]:
                nic_success, nic_msg = self._disable_network_adapter(adapter_name)
                results.append(f"[RE-ISOLATION] {nic_msg}")
                if not nic_success:
                    success = False
            
            msg = "; ".join(results)
            self.logger.warning(f"Re-isolation result: {msg}")
            return (success, msg)
            
        except Exception as e:
            self.logger.exception("Re-isolation error")
            return (False, str(e))
    
    def response_deisolate_host(self, parameters: dict) -> tuple:
        """
        De-isolate the host, restoring normal network connectivity.
        Removes firewall rules and/or re-enables network adapters.
        """
        policy = parameters.get("policy", "FIREWALL_BLOCK")
        adapter_name = parameters.get("adapter_name")
        
        self.logger.info(f"DE-ISOLATING HOST - Policy: {policy}")
        
        results = []
        success = True
        
        try:
            if policy in ["FIREWALL_BLOCK", "HYBRID"]:
                fw_success, fw_msg = self._remove_firewall_isolation()
                results.append(fw_msg)
                if not fw_success:
                    success = False
            
            if policy in ["DISABLE_NIC", "HYBRID"]:
                nic_success, nic_msg = self._enable_network_adapter(adapter_name)
                results.append(nic_msg)
                if not nic_success:
                    success = False
            
            msg = "; ".join(results)
            self.logger.info(f"De-isolation result: {msg}")
            return (success, msg)
            
        except Exception as e:
            self.logger.exception("De-isolation error")
            return (False, str(e))
    
    def _apply_firewall_isolation(self) -> tuple:
        """Apply firewall rules to block outbound traffic."""
        rule_name_out = "RANSOMRUN_ISOLATION_OUT"
        rule_name_in = "RANSOMRUN_ISOLATION_IN"
        
        try:
            # Ensure firewall is enabled
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                capture_output=True,
                timeout=30
            )
            
            # Remove any existing rules first
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_out}"],
                capture_output=True,
                timeout=30
            )
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_in}"],
                capture_output=True,
                timeout=30
            )
            
            # Add rule to block all outbound traffic
            result_out = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name_out}",
                    "dir=out",
                    "action=block",
                    "protocol=any",
                    "enable=yes"
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Add rule to block all inbound traffic (except established)
            result_in = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name_in}",
                    "dir=in",
                    "action=block",
                    "protocol=any",
                    "enable=yes"
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result_out.returncode == 0 and result_in.returncode == 0:
                return (True, "Firewall isolation applied (inbound + outbound blocked)")
            else:
                errors = []
                if result_out.returncode != 0:
                    errors.append(f"Outbound: {result_out.stderr or result_out.stdout}")
                if result_in.returncode != 0:
                    errors.append(f"Inbound: {result_in.stderr or result_in.stdout}")
                return (False, f"Firewall errors: {'; '.join(errors)}")
                
        except subprocess.TimeoutExpired:
            return (False, "Firewall command timed out")
        except Exception as e:
            return (False, f"Firewall error: {e}")
    
    def _remove_firewall_isolation(self) -> tuple:
        """Remove firewall isolation rules."""
        rule_name_out = "RANSOMRUN_ISOLATION_OUT"
        rule_name_in = "RANSOMRUN_ISOLATION_IN"
        
        try:
            result_out = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_out}"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            result_in = subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_in}"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Also try to remove legacy rule name
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=RANSOMRUN_ISOLATION"],
                capture_output=True,
                timeout=30
            )
            
            return (True, "Firewall isolation rules removed")
            
        except subprocess.TimeoutExpired:
            return (False, "Firewall command timed out")
        except Exception as e:
            return (False, f"Firewall removal error: {e}")
    
    def _disable_network_adapter(self, adapter_name: Optional[str] = None) -> tuple:
        """Disable network adapter(s) using PowerShell."""
        try:
            if adapter_name:
                # Disable specific adapter
                cmd = f'Disable-NetAdapter -Name "{adapter_name}" -Confirm:$false'
            else:
                # Get and disable all active adapters (risky - may lose connectivity)
                # For safety, we'll just disable non-primary adapters
                cmd = 'Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notlike "*Virtual*" } | Select-Object -Skip 1 | Disable-NetAdapter -Confirm:$false'
            
            result = subprocess.run(
                ["powershell", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return (True, f"Network adapter(s) disabled: {adapter_name or 'secondary adapters'}")
            else:
                # May fail if no adapters match or already disabled
                return (True, f"NIC disable attempted: {result.stderr or 'no matching adapters'}")
                
        except subprocess.TimeoutExpired:
            return (False, "PowerShell command timed out")
        except Exception as e:
            return (False, f"NIC disable error: {e}")
    
    def _enable_network_adapter(self, adapter_name: Optional[str] = None) -> tuple:
        """Re-enable network adapter(s) using PowerShell."""
        try:
            if adapter_name:
                cmd = f'Enable-NetAdapter -Name "{adapter_name}" -Confirm:$false'
            else:
                # Enable all disabled adapters
                cmd = 'Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" } | Enable-NetAdapter -Confirm:$false'
            
            result = subprocess.run(
                ["powershell", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return (True, f"Network adapter(s) enabled: {adapter_name or 'all disabled adapters'}")
            else:
                return (True, f"NIC enable attempted: {result.stderr or 'no matching adapters'}")
                
        except subprocess.TimeoutExpired:
            return (False, "PowerShell command timed out")
        except Exception as e:
            return (False, f"NIC enable error: {e}")
    
    # =========================================================================
    # RECOVERY ACTIONS
    # =========================================================================
    
    def recovery_enable_user(self, parameters: dict) -> tuple:
        """Re-enable a Windows user account that was disabled during containment."""
        username = parameters.get("username")
        
        if not username:
            return (False, "No username specified")
        
        self.logger.info(f"Re-enabling user: {username}")
        
        try:
            result = subprocess.run(
                ["net", "user", username, "/active:yes"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                msg = f"Successfully re-enabled user: {username}"
                self.logger.info(msg)
                return (True, msg)
            else:
                msg = f"net user output: {result.stdout or result.stderr}"
                self.logger.warning(msg)
                # Check if user doesn't exist
                if "not found" in msg.lower():
                    return (True, f"User {username} not found (may not exist)")
                return (False, msg)
                
        except subprocess.TimeoutExpired:
            return (False, "net user timed out")
        except Exception as e:
            return (False, str(e))
    
    def recovery_restore_files_from_quarantine(self, parameters: dict) -> tuple:
        """
        Restore files from quarantine directory to a target location.
        
        Parameters:
        - quarantine_dir: Source directory where quarantined files are stored
        - restore_target_dir: Destination directory for restored files
        """
        quarantine_dir = parameters.get("quarantine_dir", QUARANTINE_DIR)
        restore_target_dir = parameters.get("restore_target_dir", TEST_DIR)
        
        self.logger.info(f"Restoring files from {quarantine_dir} to {restore_target_dir}")
        
        try:
            quarantine_path = Path(quarantine_dir)
            restore_path = Path(restore_target_dir)
            
            if not quarantine_path.exists():
                return (True, f"Quarantine directory does not exist: {quarantine_dir}")
            
            # Create restore directory if it doesn't exist
            restore_path.mkdir(parents=True, exist_ok=True)
            
            restored_count = 0
            errors = []
            
            for filepath in quarantine_path.iterdir():
                if filepath.is_file():
                    try:
                        dest = restore_path / filepath.name
                        shutil.move(str(filepath), str(dest))
                        restored_count += 1
                        self.logger.info(f"Restored: {filepath.name}")
                    except Exception as e:
                        errors.append(f"{filepath.name}: {e}")
            
            if errors:
                msg = f"Restored {restored_count} files with {len(errors)} errors: {'; '.join(errors[:3])}"
            else:
                msg = f"Successfully restored {restored_count} files from quarantine"
            
            self.logger.info(msg)
            return (True, msg)
            
        except Exception as e:
            self.logger.exception("File restore error")
            return (False, str(e))
    
    # =========================================================================
    # NEW PLAYBOOK ACTION HANDLERS
    # =========================================================================
    
    def backup_snapshot(self, parameters: dict) -> tuple:
        """Create a backup snapshot of critical files."""
        snapshot_type = parameters.get("snapshot_type", "FILE_LEVEL")
        backup_paths = parameters.get("backup_paths", [TEST_DIR])
        
        self.logger.info(f"Creating {snapshot_type} backup snapshot")
        
        try:
            import hashlib
            from datetime import datetime
            
            # Create backup directory
            backup_dir = Path("backups") / f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            files_backed_up = 0
            total_size = 0
            manifest = []
            
            for backup_path in backup_paths:
                path = Path(backup_path)
                if not path.exists():
                    continue
                
                for file_path in path.rglob("*"):
                    if file_path.is_file():
                        try:
                            # Calculate hash
                            with open(file_path, "rb") as f:
                                file_hash = hashlib.sha256(f.read()).hexdigest()
                            
                            # Copy to backup
                            rel_path = file_path.relative_to(path)
                            dest = backup_dir / rel_path
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(file_path, dest)
                            
                            file_size = file_path.stat().st_size
                            files_backed_up += 1
                            total_size += file_size
                            
                            manifest.append({
                                "original_path": str(file_path),
                                "backup_path": str(dest),
                                "size": file_size,
                                "hash": file_hash
                            })
                            
                        except Exception as e:
                            self.logger.warning(f"Failed to backup {file_path}: {e}")
            
            # Save manifest
            manifest_file = backup_dir / "manifest.json"
            with open(manifest_file, "w") as f:
                json.dump(manifest, f, indent=2)
            
            msg = f"Backup complete: {files_backed_up} files, {total_size} bytes to {backup_dir}"
            self.logger.info(msg)
            return (True, msg)
            
        except Exception as e:
            self.logger.exception("Backup snapshot error")
            return (False, str(e))
    
    def restore_backup(self, parameters: dict) -> tuple:
        """Restore files from a backup snapshot."""
        snapshot_id = parameters.get("snapshot_id")
        restore_type = parameters.get("restore_type", "FULL")
        target_path = parameters.get("target_path")
        
        self.logger.info(f"Restoring backup snapshot {snapshot_id} (type: {restore_type})")
        
        try:
            # Find latest backup if no snapshot_id specified
            backup_base = Path("backups")
            if not backup_base.exists():
                return (False, "No backups directory found")
            
            snapshots = sorted(backup_base.glob("snapshot_*"), reverse=True)
            if not snapshots:
                return (False, "No backup snapshots found")
            
            snapshot_dir = snapshots[0]
            manifest_file = snapshot_dir / "manifest.json"
            
            if not manifest_file.exists():
                return (False, "Backup manifest not found")
            
            with open(manifest_file, "r") as f:
                manifest = json.load(f)
            
            files_restored = 0
            for item in manifest:
                try:
                    backup_path = Path(item["backup_path"])
                    original_path = Path(item["original_path"])
                    
                    if target_path:
                        # Restore to alternate location
                        dest = Path(target_path) / original_path.name
                    else:
                        # Restore to original location
                        dest = original_path
                    
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(backup_path, dest)
                    files_restored += 1
                    
                except Exception as e:
                    self.logger.warning(f"Failed to restore {item['original_path']}: {e}")
            
            msg = f"Restore complete: {files_restored}/{len(manifest)} files restored from {snapshot_dir.name}"
            self.logger.info(msg)
            return (True, msg)
            
        except Exception as e:
            self.logger.exception("Restore backup error")
            return (False, str(e))
    
    def isolate_host(self, parameters: dict) -> tuple:
        """Isolate host using specified policy."""
        policy = parameters.get("policy", "HYBRID")
        ttl_minutes = parameters.get("ttl_minutes")
        
        self.logger.info(f"Isolating host with policy: {policy}, TTL: {ttl_minutes} min")
        
        # Reuse existing isolation logic
        return self.response_isolate_host(parameters)
    
    def deisolate_host(self, parameters: dict) -> tuple:
        """Remove host isolation."""
        self.logger.info("De-isolating host (escape hatch)")
        
        # Reuse existing de-isolation logic
        return self.response_deisolate_host(parameters)
    
    def protect_backup_targets(self, parameters: dict) -> tuple:
        """Protect backup directories from modification."""
        backup_paths = parameters.get("backup_paths", ["C:\\Backups"])
        
        self.logger.info(f"Protecting backup targets: {backup_paths}")
        
        try:
            protected = []
            for path in backup_paths:
                backup_path = Path(path)
                if backup_path.exists():
                    # Set read-only attribute (simulation)
                    try:
                        subprocess.run(
                            ["attrib", "+R", str(backup_path), "/S", "/D"],
                            capture_output=True,
                            timeout=30
                        )
                        protected.append(str(backup_path))
                    except Exception as e:
                        self.logger.warning(f"Failed to protect {path}: {e}")
            
            msg = f"Protected {len(protected)} backup directories"
            self.logger.info(msg)
            return (True, msg)
            
        except Exception as e:
            self.logger.exception("Protect backup targets error")
            return (False, str(e))
    
    def collect_triage(self, parameters: dict) -> tuple:
        """Collect forensic triage data."""
        triage_type = parameters.get("triage_type", "ransomware_full")
        
        self.logger.info(f"Collecting triage data: {triage_type}")
        
        try:
            from datetime import datetime
            
            triage_dir = Path("triage") / f"triage_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            triage_dir.mkdir(parents=True, exist_ok=True)
            
            collected = []
            
            # Collect running processes
            try:
                result = subprocess.run(
                    ["tasklist", "/V", "/FO", "CSV"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                with open(triage_dir / "processes.csv", "w") as f:
                    f.write(result.stdout)
                collected.append("processes")
            except:
                pass
            
            # Collect network connections
            try:
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                with open(triage_dir / "network.txt", "w") as f:
                    f.write(result.stdout)
                collected.append("network")
            except:
                pass
            
            # Collect autoruns (registry run keys)
            try:
                result = subprocess.run(
                    ["reg", "query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                with open(triage_dir / "autoruns.txt", "w") as f:
                    f.write(result.stdout)
                collected.append("autoruns")
            except:
                pass
            
            # Collect recent file modifications
            if triage_type == "file_system":
                try:
                    recent_files = []
                    for path in [TEST_DIR]:
                        p = Path(path)
                        if p.exists():
                            for f in p.rglob("*"):
                                if f.is_file():
                                    recent_files.append({
                                        "path": str(f),
                                        "size": f.stat().st_size,
                                        "modified": f.stat().st_mtime
                                    })
                    
                    with open(triage_dir / "recent_files.json", "w") as f:
                        json.dump(recent_files, f, indent=2)
                    collected.append("file_system")
                except:
                    pass
            
            msg = f"Triage collection complete: {', '.join(collected)} -> {triage_dir}"
            self.logger.info(msg)
            return (True, msg)
            
        except Exception as e:
            self.logger.exception("Collect triage error")
            return (False, str(e))
    
    def block_ip(self, parameters: dict) -> tuple:
        """Block IP address using firewall."""
        ip_address = parameters.get("ip_address", "auto_detect")
        direction = parameters.get("direction", "outbound")
        port = parameters.get("port")
        
        self.logger.info(f"Blocking IP: {ip_address}, direction: {direction}")
        
        try:
            if ip_address == "auto_detect":
                # In real scenario, would detect C2 IP from network traffic
                ip_address = "203.0.113.0"  # TEST-NET-3 (documentation range)
            
            rule_name = f"RANSOMRUN_BLOCK_{ip_address.replace('.', '_')}"
            
            # Remove existing rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True,
                timeout=30
            )
            
            # Add blocking rule
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                f"dir={direction}",
                "action=block",
                f"remoteip={ip_address}",
                "enable=yes"
            ]
            
            if port:
                cmd.extend([f"protocol=TCP", f"remoteport={port}"])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                msg = f"Blocked {direction} traffic to {ip_address}"
                if port:
                    msg += f" on port {port}"
                self.logger.info(msg)
                return (True, msg)
            else:
                return (False, f"Firewall rule failed: {result.stderr or result.stdout}")
                
        except Exception as e:
            self.logger.exception("Block IP error")
            return (False, str(e))
    
    # =========================================================================
    # MAIN LOOP
    # =========================================================================
    
    def run(self):
        """Main agent loop."""
        # Initial registration - try but don't fail if backend unavailable
        backend_available = self.register()
        
        if not backend_available:
            self.logger.warning("Backend server not available. Running in OFFLINE mode.")
            self.logger.warning("Agent will wait for backend connection...")
            
        retry_count = 0
        max_retries = 5
        
        self.logger.info(f"Starting task polling loop (interval: {POLL_INTERVAL}s)")
        
        while True:
            try:
                if not backend_available:
                    # Try to reconnect every few attempts
                    if retry_count % 3 == 0:
                        self.logger.info(f"Attempting to connect to backend... (attempt {retry_count + 1})")
                        backend_available = self.register()
                        if backend_available:
                            self.logger.info("Successfully connected to backend!")
                    
                    retry_count += 1
                    if retry_count >= max_retries:
                        self.logger.error("Max connection retries reached. Please check:")
                        self.logger.error(f"  1. Backend server is running at {self.backend_url}")
                        self.logger.error(f"  2. Network connectivity from {self.ip_address} to backend")
                        self.logger.error("  3. Windows Firewall allows port 8000")
                        self.logger.error("\nExiting agent. Fix the issues and restart.")
                        break
                    
                    time.sleep(POLL_INTERVAL)
                    continue
                
                # Poll for tasks
                task = self.poll_for_task()
                
                if task.get("task_id"):
                    self.execute_task(task)
                
                # Re-register periodically to update status
                if not self.register():
                    backend_available = False
                    self.logger.warning("Lost connection to backend. Entering reconnection mode...")
                
                # Wait before next poll
                time.sleep(POLL_INTERVAL)
                
            except KeyboardInterrupt:
                self.logger.info("Agent stopped by user")
                break
            except Exception as e:
                self.logger.exception(f"Main loop error: {e}")
                time.sleep(POLL_INTERVAL)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def remove_isolation():
    """Remove network isolation (restore connectivity)."""
    print("Removing network isolation...")
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", "name=RANSOMRUN_ISOLATION"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("Isolation removed successfully")
        else:
            print(f"Result: {result.stdout or result.stderr}")
    except Exception as e:
        print(f"Error: {e}")


def restore_files():
    """Restore 'encrypted' files by removing .locked extension."""
    print(f"Restoring files in {TEST_DIR}...")
    try:
        test_path = Path(TEST_DIR)
        if not test_path.exists():
            print("Test directory does not exist")
            return
        
        restored = 0
        for filepath in test_path.iterdir():
            if filepath.suffix == ".locked":
                # Remove .locked extension
                new_name = filepath.stem  # This removes .locked
                new_path = filepath.with_name(new_name)
                filepath.rename(new_path)
                print(f"Restored: {filepath.name} -> {new_path.name}")
                restored += 1
        
        print(f"Restored {restored} files")
    except Exception as e:
        print(f"Error: {e}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RANSOMRUN Windows Agent")
    parser.add_argument("--restore", action="store_true", help="Restore 'encrypted' files")
    parser.add_argument("--unisolate", action="store_true", help="Remove network isolation")
    parser.add_argument("--server", type=str, help="Backend server URL")
    parser.add_argument("--agent-id", type=str, help="Custom agent ID")
    
    args = parser.parse_args()
    
    # Handle utility commands
    if args.restore:
        restore_files()
        sys.exit(0)
    
    if args.unisolate:
        remove_isolation()
        sys.exit(0)
    
    # Override config from command line
    if args.server:
        BACKEND_URL = args.server
    
    agent_id = args.agent_id or AGENT_ID
    
    # Create and run agent
    agent = RansomRunAgent(BACKEND_URL, agent_id)
    agent.run()
