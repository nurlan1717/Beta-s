# Agent Integration Guide - Advanced Ransomware Simulation

## Overview

The advanced ransomware simulation has been successfully integrated into the RansomRun agent system. This guide explains how the integration works and how to use it.

---

## 🔗 Integration Architecture

### Components Integrated

1. **`ransomware_template.py`** - Professional ransomware GUI with advanced features
2. **`polymorphic_builder.py`** - Automated payload builder with mutation engine
3. **`agent.py`** - Enhanced with polymorphic ransomware support

### Integration Points

#### 1. Enhanced GUI Launcher (`_launch_gui_ransomware`)

The agent now prioritizes the advanced ransomware template:

```python
# Priority 1: Advanced professional ransomware template
gui_script = "Advanced_Simulation/ransomware_template.py"

# Priority 2: Legacy WannaCry-style GUI
gui_script = "Advanced_Simulation/wana_decrypt0r_gui.py"
```

**Features:**
- Automatic fallback to legacy GUI if advanced template not found
- Logs GUI type in events (professional_polymorphic vs wannacry_style)
- Tracks advanced features: fullscreen_takeover, countdown_timer, file_encryption_log, restore_capability

#### 2. New Polymorphic Launcher (`_launch_polymorphic_ransomware`)

Completely new method that integrates the polymorphic builder:

```python
def _launch_polymorphic_ransomware(self):
    """Launch advanced polymorphic ransomware with builder integration."""
```

**Workflow:**
1. Locates `polymorphic_builder.py`
2. Executes builder with `--auto-build` flag
3. Extracts payload hash from build output
4. Logs polymorphic build event (T1027)
5. Executes generated `svc_host_update.py` payload
6. Logs polymorphic execution event (T1486)
7. Falls back to standard GUI if any step fails

**MITRE ATT&CK Coverage:**
- **T1027** - Obfuscated Files or Information (polymorphic mutation)
- **T1486** - Data Encrypted for Impact (ransomware execution)

#### 3. Updated Simulation Logic

The `simulate_ransomware` method now detects polymorphic mode:

```python
polymorphic_mode = scenario_config.get("polymorphic_mode", False)

if polymorphic_mode or scenario_key == "advanced_polymorphic":
    self._launch_polymorphic_ransomware()
else:
    self._launch_gui_ransomware()
```

---

## 🚀 Usage

### Method 1: Via Scenario Configuration

Enable polymorphic mode in your scenario JSON:

```json
{
  "scenario_key": "crypto_advanced",
  "scenario_config": {
    "enable_gui_popup": true,
    "polymorphic_mode": true,
    "directories_to_target": ["C:\\RansomTest"],
    "file_extensions": [".txt", ".docx", ".xlsx"],
    "rename_pattern": ".locked",
    "simulate_vssadmin": true,
    "simulate_persistence": true
  }
}
```

### Method 2: Via Scenario Key

Use the `advanced_polymorphic` scenario key:

```json
{
  "scenario_key": "advanced_polymorphic",
  "scenario_config": {
    "directories_to_target": ["C:\\RansomTest"],
    "file_extensions": [".txt", ".docx", ".xlsx"]
  }
}
```

This automatically triggers polymorphic mode.

### Method 3: Direct Builder Execution

Run the polymorphic builder manually:

```bash
# Interactive mode
python Advanced_Simulation/polymorphic_builder.py

# Automated build
python Advanced_Simulation/polymorphic_builder.py --auto-build

# Build and execute
python Advanced_Simulation/polymorphic_builder.py --build-and-run
```

---

## 📊 Event Logging

### GUI Ransomware Launch Event

```json
{
  "event_type": "GUI_RANSOMWARE_LAUNCHED",
  "timestamp": "2024-12-16T20:00:00",
  "details": {
    "technique": "T1486",
    "gui_script": "C:\\...\\ransomware_template.py",
    "gui_type": "professional_polymorphic",
    "visual_impact": true,
    "features": [
      "fullscreen_takeover",
      "countdown_timer", 
      "file_encryption_log",
      "restore_capability"
    ]
  }
}
```

### Polymorphic Build Event

```json
{
  "event_type": "POLYMORPHIC_BUILD",
  "timestamp": "2024-12-16T20:00:05",
  "details": {
    "technique": "T1027",
    "builder_script": "C:\\...\\polymorphic_builder.py",
    "payload_hash": "abc123def456...",
    "mutation_applied": true
  }
}
```

### Polymorphic Execution Event

```json
{
  "event_type": "POLYMORPHIC_EXECUTION",
  "timestamp": "2024-12-16T20:00:10",
  "details": {
    "technique": "T1486",
    "payload_path": "C:\\...\\svc_host_update.py",
    "hash": "abc123def456...",
    "evasion_level": "advanced"
  }
}
```

---

## 🎯 Scenario Examples

### Basic Advanced GUI

```json
{
  "scenario_key": "crypto_basic",
  "scenario_config": {
    "enable_gui_popup": true,
    "directories_to_target": ["C:\\RansomTest"],
    "file_extensions": [".txt", ".docx"],
    "rename_pattern": ".locked"
  }
}
```

**Result:** Launches professional ransomware GUI with file encryption simulation

### Full Polymorphic Attack

```json
{
  "scenario_key": "advanced_polymorphic",
  "scenario_config": {
    "enable_gui_popup": true,
    "polymorphic_mode": true,
    "directories_to_target": ["C:\\RansomTest"],
    "file_extensions": [".txt", ".docx", ".xlsx", ".pdf"],
    "rename_pattern": ".locked",
    "simulate_vssadmin": true,
    "simulate_persistence": true,
    "simulate_exfiltration": true,
    "simulate_network_beacon": true,
    "intensity_level": 3
  }
}
```

**Result:** 
1. Builds unique polymorphic payload
2. Launches professional GUI
3. Simulates file encryption
4. Deletes shadow copies
5. Creates persistence
6. Stages exfiltration
7. Sends network beacons

### APT-Style Full Chain with Polymorphism

```json
{
  "scenario_key": "apt_full_chain",
  "scenario_config": {
    "enable_gui_popup": true,
    "polymorphic_mode": true,
    "directories_to_target": ["C:\\RansomTest"],
    "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg"],
    "rename_pattern": ".locked",
    "simulate_vssadmin": true,
    "simulate_persistence": true,
    "simulate_exfiltration": true,
    "simulate_network_beacon": true,
    "simulate_lateral_movement": true,
    "simulate_credential_dump": true,
    "simulate_registry_persistence": true,
    "simulate_process_injection": true,
    "simulate_defense_evasion": true,
    "intensity_level": 5
  }
}
```

**Result:** Complete APT kill chain with polymorphic evasion

---

## 🔍 Detection Points

### File System Indicators

- **Polymorphic payload:** `Advanced_Simulation/svc_host_update.py`
- **Build history:** `Advanced_Simulation/build_history.json`
- **Encrypted files:** `*.locked` extension
- **Ransom note:** `!!!READ_ME_TO_DECRYPT!!!.txt`
- **Backup directory:** `Advanced_Simulation/.simulation_backup/`
- **Target directory:** `Advanced_Simulation/target_data/`

### Process Indicators

- **Builder process:** `python.exe polymorphic_builder.py --auto-build`
- **Payload process:** `python.exe svc_host_update.py`
- **GUI process:** `python.exe ransomware_template.py`

### Network Indicators

- Agent communication to backend
- Simulated C2 beacons (logged, not actual)

### Registry Indicators

- Simulated persistence keys (logged, not created)
- Run key modifications (simulated)

---

## 🛡️ Safety Features

### Automatic Fallbacks

1. **Builder not found** → Falls back to direct template execution
2. **Build fails** → Falls back to direct template execution
3. **Payload not generated** → Falls back to direct template execution
4. **Template not found** → Falls back to legacy GUI
5. **All GUIs missing** → Logs warning, continues with file operations only

### Backup System

All files are automatically backed up before "encryption":

```
target_data/document.txt → .simulation_backup/document.txt
target_data/document.txt → target_data/document.txt.locked
```

### Restore Capability

The GUI includes a prominent **"UNLOCK / RESTORE SYSTEM"** button that:
1. Restores all files from `.simulation_backup/`
2. Removes all `.locked` files
3. Deletes ransom notes
4. Exits cleanly

---

## 📈 SIEM Integration

### Events Sent to Backend

All events are automatically sent to the SIEM backend via:

```python
POST /api/siem/agent/extended-result
{
  "run_id": 123,
  "files_affected": [...],
  "iocs": [...],
  "metrics": {...},
  "events": [
    {
      "event_type": "POLYMORPHIC_BUILD",
      "timestamp": "...",
      "details": {...}
    },
    {
      "event_type": "POLYMORPHIC_EXECUTION",
      "timestamp": "...",
      "details": {...}
    }
  ]
}
```

### Dashboard Visibility

Events appear in:
- **SIEM Dashboard** - Real-time event stream
- **Attack Timeline** - Chronological view
- **IOC Tracker** - File paths, hashes, registry keys
- **Metrics Panel** - Execution time, files touched, alerts expected

---

## 🔧 Configuration

### Builder Configuration

Edit `polymorphic_builder.py`:

```python
class BuilderConfig:
    TEMPLATE_FILE = "ransomware_template.py"
    OUTPUT_PAYLOAD = "svc_host_update.py"
    
    # Polymorphism Strength (1-10)
    MUTATION_LEVEL = 7  # Adjust for more/less evasion
```

### Simulation Configuration

Edit `ransomware_template.py`:

```python
class SimulationConfig:
    TARGET_DIR = "target_data"
    COUNTDOWN_HOURS = 72
    ENCRYPTION_DELAY = 0.3
    
    # Evasion
    ENABLE_SANDBOX_DETECTION = True
    ENABLE_VM_DETECTION = True
```

---

## 🧪 Testing

### Test 1: Basic GUI Launch

```bash
# From agent directory
cd agent
python agent.py
```

Trigger scenario with `enable_gui_popup: true`

**Expected:** Professional GUI launches with countdown timer

### Test 2: Polymorphic Build

```bash
# From Advanced_Simulation directory
cd Advanced_Simulation
python polymorphic_builder.py --auto-build
```

**Expected:** 
- Build completes successfully
- `svc_host_update.py` created
- Unique hash generated
- Build logged in `build_history.json`

### Test 3: Full Integration

Trigger scenario with `polymorphic_mode: true`

**Expected:**
1. Agent receives task
2. Builder executes automatically
3. Payload generated with unique hash
4. GUI launches
5. Files "encrypted"
6. Events logged to SIEM
7. Restore button works

---

## 🐛 Troubleshooting

### Issue: Builder Not Found

```
WARNING: Polymorphic builder not found: C:\...\polymorphic_builder.py
```

**Solution:** Ensure `Advanced_Simulation/polymorphic_builder.py` exists

### Issue: Build Fails

```
WARNING: Polymorphic build failed: ...
```

**Solution:** 
1. Check `ransomware_template.py` exists
2. Verify Python syntax in template
3. Check file permissions
4. Run builder manually to see detailed error

### Issue: Payload Not Executed

```
WARNING: Generated payload not found, using template directly
```

**Solution:**
1. Check build completed successfully
2. Verify `svc_host_update.py` was created
3. Check file permissions

### Issue: GUI Doesn't Launch

```
WARNING: GUI script not found: ...
```

**Solution:**
1. Verify `ransomware_template.py` exists in `Advanced_Simulation/`
2. Check fallback `wana_decrypt0r_gui.py` exists
3. Verify file paths in agent configuration

---

## 📚 Additional Resources

- **Main README:** `ADVANCED_RANSOMWARE_README.md`
- **Builder Documentation:** See polymorphic_builder.py docstrings
- **Template Documentation:** See ransomware_template.py docstrings
- **Agent Documentation:** See agent.py header comments

---

## ✅ Integration Checklist

- [x] `ransomware_template.py` created in `Advanced_Simulation/`
- [x] `polymorphic_builder.py` created in `Advanced_Simulation/`
- [x] `agent.py` updated with `_launch_gui_ransomware()` enhancements
- [x] `agent.py` updated with `_launch_polymorphic_ransomware()` method
- [x] `simulate_ransomware()` updated to detect polymorphic mode
- [x] Builder supports `--auto-build` command-line argument
- [x] Event logging for GUI launches
- [x] Event logging for polymorphic builds
- [x] Event logging for polymorphic executions
- [x] Automatic fallback mechanisms
- [x] SIEM integration maintained
- [x] Documentation created

---

**Integration Status:** ✅ **COMPLETE**

The advanced ransomware simulation is fully integrated into the RansomRun agent system and ready for use in security training and detection testing scenarios.
