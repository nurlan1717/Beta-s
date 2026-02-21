# Advanced Ransomware Simulation - Professional Edition

## Team: DON'T WANNA CRY

**⚠️ WARNING: Educational purposes only - For security training and detection testing**

---

## 📋 Overview

This is a professional-grade ransomware simulation designed for cybersecurity training, detection testing, and security awareness demonstrations. It implements realistic ransomware behavior patterns while maintaining complete safety through controlled simulation.

### Key Features

✅ **Advanced Polymorphic Engine** - Generates unique payloads for each build
✅ **Anti-Detection Techniques** - Sandbox detection, VM detection, behavioral evasion
✅ **Realistic GUI** - Professional ransomware interface with countdown timer
✅ **Safe File Operations** - Automatic backup and restore functionality
✅ **Build History Tracking** - Complete audit trail of all generated payloads
✅ **Configurable Behavior** - Adjustable mutation levels and target settings

---

## 🏗️ Architecture

### Components

1. **`ransomware_template.py`** - Core ransomware simulation engine
2. **`polymorphic_builder.py`** - Advanced payload builder with mutation capabilities
3. **`svc_host_update.py`** - Generated payload (created by builder)
4. **`build_history.json`** - Build audit log

### File Structure

```
Advanced_Simulation/
├── ransomware_template.py      # Core simulation template
├── polymorphic_builder.py      # Polymorphic builder
├── svc_host_update.py          # Generated payload
├── build_history.json          # Build history log
├── target_data/                # Target directory for simulation
│   └── !!!READ_ME_TO_DECRYPT!!!.txt
└── .simulation_backup/         # Automatic backup storage
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- tkinter (usually included with Python)
- Windows OS (for full feature support)

### Installation

```bash
cd Advanced_Simulation
```

### Usage

#### Option 1: Interactive Builder (Recommended)

```bash
python polymorphic_builder.py
```

**Menu Options:**
- `[1]` Build New Payload - Generate unique payload
- `[2]` Build & Execute - Build and run immediately
- `[3]` Execute Existing Payload - Run previously built payload
- `[4]` View Build History - Show all builds
- `[5]` Configuration - View current settings
- `[0]` Exit

#### Option 2: Direct Execution

```bash
# Build payload
python polymorphic_builder.py

# Execute payload
python svc_host_update.py
```

#### Option 3: Template Direct Run

```bash
python ransomware_template.py
```

---

## 🔧 Configuration

### Builder Configuration (`polymorphic_builder.py`)

```python
class BuilderConfig:
    TEMPLATE_FILE = "ransomware_template.py"
    OUTPUT_PAYLOAD = "svc_host_update.py"
    
    # Obfuscation Settings
    ENABLE_JUNK_CODE = True
    ENABLE_VARIABLE_RENAMING = True
    ENABLE_STRING_ENCODING = True
    
    # Polymorphism Strength (1-10)
    MUTATION_LEVEL = 7
```

### Simulation Configuration (`ransomware_template.py`)

```python
class SimulationConfig:
    TARGET_DIR = "target_data"
    BACKUP_DIR = ".simulation_backup"
    
    # File Extensions to Target
    TARGET_EXTENSIONS = ['.txt', '.doc', '.docx', '.pdf', ...]
    
    # Timing
    COUNTDOWN_HOURS = 72
    ENCRYPTION_DELAY = 0.3
    
    # Evasion
    ENABLE_SANDBOX_DETECTION = True
    ENABLE_VM_DETECTION = True
```

---

## 🎯 Features Breakdown

### 1. Polymorphic Engine

The builder generates unique payloads for each build using multiple mutation techniques:

- **Junk Code Injection** - Adds random code blocks
- **Dead Code Insertion** - Unreachable code branches
- **NOP Operations** - No-operation statements
- **Entropy Padding** - Random data blocks
- **Timestamp Mutations** - Time-based variations
- **Mathematical Obfuscation** - Random calculations

**Result:** Each build has a unique hash signature, evading signature-based detection.

### 2. Anti-Analysis Techniques

#### Sandbox Detection
- Checks for common sandbox directories
- Detects sandbox usernames
- Identifies analysis environments

#### VM Detection
- Identifies virtual machine platforms
- Checks system manufacturer strings
- Detects hypervisor presence

#### Behavioral Evasion
- Mouse movement detection
- Sleep acceleration detection
- Time-based delays

### 3. Realistic Ransomware Behavior

#### File Operations
- Targets common file extensions
- Creates automatic backups
- Simulates encryption via file renaming
- Generates professional ransom note

#### Visual Interface
- Fullscreen takeover
- Countdown timer (72 hours)
- Real-time activity log
- Professional design

#### Persistence Simulation
- Startup registry simulation
- Wallpaper change capability
- System-wide impact demonstration

---

## 🔒 Safety Features

### Automatic Backup System

All files are automatically backed up before "encryption":

```
target_data/document.txt → .simulation_backup/document.txt
target_data/document.txt → target_data/document.txt.locked
```

### One-Click Restore

The GUI includes a prominent **"UNLOCK / RESTORE SYSTEM"** button that:
1. Restores all files from backup
2. Removes all .locked files
3. Deletes ransom note
4. Exits simulation cleanly

### Emergency Exit

- Press `ESC` key for emergency exit
- Window close button (with confirmation)
- Ctrl+C in terminal

---

## 📊 Build History

The builder maintains a complete audit log of all generated payloads:

```json
{
  "builds": [
    {
      "build_id": "20241216200000-ABC12345",
      "build_number": 1,
      "timestamp": "2024-12-16T20:00:00",
      "template_hash": "abc123...",
      "payload_hash": "def456...",
      "mutation_level": 7,
      "mutations": ["Junk Code Injection", "Dead Code Insertion", ...],
      "output_file": "svc_host_update.py",
      "file_size": 45678
    }
  ]
}
```

---

## 🎓 Educational Use Cases

### 1. Security Awareness Training
- Demonstrate ransomware behavior to employees
- Show real-world attack patterns
- Educate on prevention strategies

### 2. Detection Testing
- Test antivirus effectiveness
- Validate EDR solutions
- Benchmark behavioral detection

### 3. Incident Response Training
- Practice ransomware response procedures
- Test backup and recovery processes
- Simulate crisis management

### 4. Red Team Exercises
- Realistic attack simulation
- Test security controls
- Validate detection capabilities

---

## 🛡️ Detection Indicators

### File System Indicators
- Creation of `.locked` files
- Ransom note: `!!!READ_ME_TO_DECRYPT!!!.txt`
- Backup directory: `.simulation_backup/`
- Mass file renaming activity

### Behavioral Indicators
- Rapid file system changes
- Fullscreen GUI takeover
- High CPU usage during "encryption"
- Suspicious process name: `svc_host_update.py`

### Network Indicators (Future)
- C2 communication simulation
- Data exfiltration patterns
- Tor network usage

---

## 🔬 Advanced Features

### Polymorphic Mutations

Each build applies multiple mutation techniques:

| Technique | Description | Detection Evasion |
|-----------|-------------|-------------------|
| Junk Code | Random code blocks | ✅ Signature bypass |
| Dead Code | Unreachable branches | ✅ Heuristic evasion |
| Entropy Padding | Random data | ✅ Hash mutation |
| Timestamp Mutations | Time-based changes | ✅ Unique builds |
| Math Obfuscation | Random calculations | ✅ Behavioral variance |

### Evasion Techniques

```python
# Sandbox Detection
if EvasionTechniques.detect_sandbox():
    # Alter behavior or exit

# VM Detection  
if EvasionTechniques.detect_vm():
    # Modify execution path

# Sleep Evasion
if not EvasionTechniques.sleep_evasion():
    # Detected accelerated time
```

---

## 📈 Customization Guide

### Modify Target Extensions

```python
TARGET_EXTENSIONS = [
    '.txt', '.doc', '.docx',  # Documents
    '.jpg', '.png', '.gif',   # Images
    '.db', '.sql',            # Databases
    # Add custom extensions
]
```

### Adjust Mutation Level

```python
# Low (1-3): Minimal mutations, faster builds
# Medium (4-7): Balanced approach
# High (8-10): Maximum evasion, larger files
MUTATION_LEVEL = 7
```

### Change Visual Theme

```python
BG_COLOR = "#0a0a0a"      # Background
TXT_COLOR = "#00ff41"     # Text
ALERT_COLOR = "#ff0000"   # Alerts
WARNING_COLOR = "#ffaa00" # Warnings
```

### Modify Countdown Timer

```python
COUNTDOWN_HOURS = 72  # Default: 72 hours
# Change to any value (e.g., 24, 48, 96)
```

---

## 🧪 Testing Scenarios

### Scenario 1: Basic Simulation
```bash
python polymorphic_builder.py
# Select [2] Build & Execute
# Observe behavior
# Click "UNLOCK / RESTORE SYSTEM"
```

### Scenario 2: Detection Testing
```bash
# Disable antivirus temporarily
python polymorphic_builder.py
# Build multiple payloads
# Compare detection rates
```

### Scenario 3: Incident Response
```bash
# Run simulation
# Practice response procedures:
# 1. Identify infection
# 2. Isolate system
# 3. Analyze behavior
# 4. Restore from backup
```

---

## 📝 Build Process

### Step-by-Step Build Flow

1. **Template Validation**
   - Verify template file exists
   - Calculate template hash

2. **Content Loading**
   - Read template source code
   - Parse structure

3. **Mutation Application**
   - Apply junk code injection
   - Insert dead code branches
   - Add entropy padding
   - Generate timestamp markers
   - Apply mathematical obfuscation

4. **Payload Generation**
   - Write mutated content
   - Calculate payload hash
   - Record build metadata

5. **History Logging**
   - Save build information
   - Update build counter
   - Store hash signatures

---

## 🎨 GUI Features

### Main Interface Components

1. **Critical Alert Header**
   - Red background
   - Large warning text
   - Attention-grabbing design

2. **Team Banner**
   - "DON'T WANNA CRY" branding
   - Professional typography

3. **Information Display**
   - Clear threat description
   - File encryption status
   - Recovery instructions

4. **Countdown Timer**
   - 72-hour countdown
   - Large digital display
   - Red color for urgency

5. **Activity Log**
   - Real-time encryption progress
   - Color-coded messages
   - Scrollable output

6. **Restore Button**
   - Prominent placement
   - Clear labeling
   - One-click recovery

---

## 🔍 Troubleshooting

### Issue: Template Not Found
```
[-] Error: Template file 'ransomware_template.py' not found!
```
**Solution:** Ensure you're in the `Advanced_Simulation` directory

### Issue: Permission Denied
```
[-] Error: Permission denied when creating files
```
**Solution:** Run with appropriate permissions or change target directory

### Issue: GUI Not Displaying
```
TclError: no display name and no $DISPLAY environment variable
```
**Solution:** Ensure X server is running or use Windows environment

### Issue: Files Not Restoring
**Solution:** Check `.simulation_backup/` directory exists and contains backups

---

## 📚 Technical Details

### Hash Calculation
```python
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
```

### Build ID Generation
```python
def generate_build_id():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"{timestamp}-{random_suffix}"
```

### File Backup Process
```python
def backup_file(filepath):
    backup_path = os.path.join(BACKUP_DIR, os.path.basename(filepath))
    with open(filepath, 'rb') as src:
        with open(backup_path, 'wb') as dst:
            dst.write(src.read())
```

---

## 🎯 Best Practices

### For Security Training
1. ✅ Always inform participants beforehand
2. ✅ Use isolated test environment
3. ✅ Have backup and recovery plan
4. ✅ Document all activities
5. ✅ Debrief after simulation

### For Detection Testing
1. ✅ Test in controlled environment
2. ✅ Monitor all security tools
3. ✅ Document detection results
4. ✅ Compare multiple builds
5. ✅ Analyze false positives/negatives

### For Development
1. ✅ Keep template and builder separate
2. ✅ Maintain build history
3. ✅ Test all mutations
4. ✅ Validate backup functionality
5. ✅ Document code changes

---

## 🚨 Ethical Guidelines

### ⚠️ DO NOT:
- ❌ Use on systems without authorization
- ❌ Deploy in production environments
- ❌ Distribute to unauthorized parties
- ❌ Remove safety features
- ❌ Use for malicious purposes

### ✅ DO:
- ✅ Use for authorized training only
- ✅ Maintain proper documentation
- ✅ Keep in controlled environments
- ✅ Respect privacy and security
- ✅ Follow organizational policies

---

## 📞 Support & Documentation

### File Locations
- Template: `ransomware_template.py`
- Builder: `polymorphic_builder.py`
- Payload: `svc_host_update.py`
- History: `build_history.json`

### Log Files
- Build logs in console output
- Activity logs in GUI
- History in JSON format

---

## 🔄 Version History

### v2.0 - Professional Edition (Current)
- ✅ Advanced polymorphic engine
- ✅ Multiple mutation techniques
- ✅ Build history tracking
- ✅ Enhanced GUI design
- ✅ Improved evasion techniques
- ✅ Comprehensive documentation

### v1.0 - Basic Edition
- Basic file encryption simulation
- Simple GUI
- Manual restore process

---

## 📖 Additional Resources

### Recommended Reading
- MITRE ATT&CK: Ransomware Techniques
- NIST Cybersecurity Framework
- Ransomware Response Guidelines
- Incident Response Best Practices

### Related Tools
- Malware analysis sandboxes
- EDR testing frameworks
- Security awareness platforms
- Incident response tools

---

## 🏆 Credits

**Team:** DON'T WANNA CRY  
**Purpose:** Security Training & Education  
**License:** Educational Use Only  

---

## ⚖️ Legal Disclaimer

This software is provided for **EDUCATIONAL PURPOSES ONLY**. The authors and contributors are not responsible for any misuse or damage caused by this program. Use only in authorized environments with proper permissions.

By using this software, you agree to:
- Use only for legitimate security training
- Obtain proper authorization before deployment
- Maintain ethical standards
- Comply with all applicable laws and regulations

---

**Stay Safe. Stay Secure. Stay Educated.**

*Last Updated: December 2024*
