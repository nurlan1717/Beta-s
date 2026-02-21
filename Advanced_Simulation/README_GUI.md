# Wana Decrypt0r 3.0 - Advanced Ransomware GUI Simulation

## Overview

High-fidelity ransomware training simulation with full-screen GUI lockdown, real encryption, and MITRE ATT&CK technique demonstrations.

## Features

✅ **Full-Screen GUI Lockdown** - Simulates real ransomware behavior with aggressive window control  
✅ **Real Encryption** - Uses Fernet (AES-128) encryption with proper key management  
✅ **MITRE ATT&CK Techniques**:
- T1486: Data Encrypted for Impact
- T1490: Inhibit System Recovery (VSS deletion simulation)
- T1021: Remote Services (Lateral movement simulation)

✅ **Training Mode** - Includes decryption capability for educational purposes  
✅ **Visual Effects** - Pulsing lock icon, countdown timer, terminal-style activity log  
✅ **Safe by Design** - Only targets `target_data` directory

## Requirements

```bash
pip install cryptography
```

**Optional**: If `cryptography` is not installed, the simulation runs in "simulation mode" with fake encryption.

## Usage

### 1. Basic Execution

```bash
cd Advanced_Simulation
python wana_decrypt0r_gui.py
```

### 2. What Happens

1. **Initialization Phase**:
   - Creates `target_data` directory with sample files
   - Generates encryption key (`encryption_key.key`)
   - Displays full-screen ransomware GUI

2. **Encryption Phase** (Background Thread):
   - Simulates VSS shadow copy deletion (T1490)
   - Simulates lateral movement to network shares (T1021)
   - Encrypts all files in `target_data` directory
   - Renames files with `.locked` extension
   - Drops ransom note (`READ_ME_NOW.txt`)

3. **GUI Display**:
   - Full-screen lock with payment demand
   - 72-hour countdown timer
   - Real-time activity log showing MITRE techniques
   - Pulsing red lock icon

4. **Recovery**:
   - Click "I UNDERSTAND - RESTORE MY FILES (DECRYPT)"
   - Confirm you learned from the simulation
   - Files are automatically decrypted and restored

## File Structure

```
Advanced_Simulation/
├── wana_decrypt0r_gui.py       # Main GUI ransomware simulation
├── loader.py                    # Polymorphic loader (existing)
├── README.md                    # Original documentation
├── README_GUI.md                # This file
├── target_data/                 # Created automatically
│   ├── confidential_hr.xlsx
│   ├── q3_financials.pdf
│   ├── ceo_passwords.txt
│   └── network_map.png
└── encryption_key.key           # Generated during execution
```

## Safety Features

1. **Isolated Target Directory**: Only encrypts files in `target_data/`
2. **Key Preservation**: Encryption key is saved for recovery
3. **Decryption Built-In**: Training mode allows full file restoration
4. **Simulation Markers**: All activities are clearly marked as simulation
5. **No Network Activity**: No actual C2 communication

## Integration with RansomRun Backend

This simulation can be triggered by the RansomRun agent when executing advanced scenarios:

```python
# In agent.py, the simulation can be launched via subprocess
import subprocess

def launch_gui_ransomware():
    """Launch GUI ransomware simulation."""
    subprocess.Popen([
        "python",
        "Advanced_Simulation/wana_decrypt0r_gui.py"
    ], creationflags=subprocess.CREATE_NEW_CONSOLE)
```

## Educational Value

### For Blue Team Training:
- Experience realistic ransomware GUI behavior
- Understand user impact and psychological tactics
- Practice incident response procedures
- Learn to identify MITRE ATT&CK techniques in action

### For Red Team Training:
- Study ransomware deployment techniques
- Understand encryption workflows
- Learn about lateral movement patterns
- Practice evasion techniques

## MITRE ATT&CK Mapping

| Technique | ID | Description | Simulation |
|-----------|-----|-------------|------------|
| Data Encrypted for Impact | T1486 | File encryption | Real Fernet encryption |
| Inhibit System Recovery | T1490 | VSS deletion | Command simulation |
| Remote Services | T1021 | Lateral movement | File drop to shares |

## Troubleshooting

### GUI Doesn't Appear
- Ensure tkinter is installed: `python -m tkinter`
- Check if another instance is running
- Verify Python version (3.7+)

### Encryption Fails
- Install cryptography: `pip install cryptography`
- Or run in simulation mode (automatic fallback)

### Can't Exit GUI
- This is intentional! Click the decrypt button
- Or use Task Manager (Ctrl+Shift+Esc) to end Python process

### Files Not Decrypting
- Ensure `encryption_key.key` exists
- Check if cryptography library is installed
- Verify files have `.locked` extension

## Advanced Usage

### Custom Target Directory

Edit the configuration in `wana_decrypt0r_gui.py`:

```python
TARGET_DIR = "custom_target_folder"
```

### Disable Full-Screen Mode

Comment out these lines for testing:

```python
# self.root.attributes("-fullscreen", True)
# self.root.attributes("-topmost", True)
# self.root.overrideredirect(True)
```

### Add Custom Files

Place your own test files in `target_data/` before running.

## Cleanup

After training session:

```bash
# Remove encrypted files
rm -rf target_data/*.locked

# Remove encryption key
rm encryption_key.key

# Remove ransom note
rm target_data/READ_ME_NOW.txt

# Or restore using the GUI decrypt button
```

## Legal Notice

⚠️ **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- Cybersecurity training
- Authorized penetration testing
- Security awareness demonstrations
- Incident response practice

**DO NOT USE** on systems you don't own or have explicit permission to test.

## Credits

Part of the **RansomRun** ransomware simulation platform.

- Backend: FastAPI + SQLAlchemy
- Agent: Python Windows agent
- GUI Simulation: Tkinter + Cryptography
- MITRE ATT&CK Framework integration

---

**Remember**: The best defense against ransomware is prevention, backups, and training!
