"""Seed initial data for RANSOMRUN."""

from sqlalchemy.orm import Session
from .models import Scenario, Playbook, ScenarioCategory
from . import crud


# Advanced scenario configurations
SCENARIO_CONFIGS = {
    "crypto_basic": {
        "directories_to_target": ["C:\\RansomTest"],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png"],
        "rename_pattern": ".locked",
        "ransom_note": {
            "filename": "README_RESTORE.txt",
            "content": """YOUR FILES HAVE BEEN ENCRYPTED!

All your important files have been encrypted with military-grade encryption.
To recover your files, you need to pay 0.5 BTC to the following address:

    1A2B3C4D5E6F7G8H9I0J (SIMULATION - NOT REAL)

After payment, contact: simulation@ransomrun.local

WARNING: This is a SIMULATION for security training purposes.
Your files have only been renamed, not actually encrypted.
Run the restore utility to recover your files.

--- RANSOMRUN TRAINING PLATFORM ---""",
            "locations": ["target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": False,
        "simulate_exfiltration": False,
        "simulate_network_beacon": False,
        "intensity_level": 2,
        "optional_delay_seconds": 0,
        "tags": ["MITRE:T1486", "MITRE:T1490", "TRAINING:BEGINNER"]
    },
    
    "crypto_aggressive": {
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents",
            "C:\\RansomLab"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".pptx", ".csv", ".json", ".xml"],
        "rename_pattern": ".crypted",
        "ransom_note": {
            "filename": "!!! READ_ME !!!.txt",
            "content": """CRITICAL SECURITY ALERT - ALL FILES ENCRYPTED

Your network has been compromised. All files on this system and connected
drives have been encrypted using RSA-4096 + AES-256.

DO NOT:
- Attempt to decrypt files yourself
- Rename encrypted files
- Contact law enforcement

TO RECOVER:
1. Purchase 2.0 BTC
2. Send to: 1SIMULATION2ADDRESS3 (NOT REAL)
3. Email proof to: aggressive@ransomrun.local

Time remaining: 72:00:00

--- RANSOMRUN AGGRESSIVE SIMULATION ---""",
            "locations": ["target_root", "desktop"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": False,
        "simulate_network_beacon": True,
        "intensity_level": 4,
        "optional_delay_seconds": 5,
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1547", "TRAINING:ADVANCED"]
    },
    
    "locker_desktop": {
        "directories_to_target": [],
        "file_extensions": [],
        "rename_pattern": "",
        "ransom_note": {
            "filename": "LOCKED_SCREEN.txt",
            "content": """╔══════════════════════════════════════════════════════════════╗
║                    SYSTEM LOCKED                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                                ║
║  Your computer has been locked due to suspicious activity.    ║
║                                                                ║
║  To unlock, pay $500 in Bitcoin to:                           ║
║  1LOCKER2SIM3ADDRESS (SIMULATION ONLY)                        ║
║                                                                ║
║  Enter unlock code: ____________                               ║
║                                                                ║
║  --- RANSOMRUN LOCKER SIMULATION ---                          ║
╚══════════════════════════════════════════════════════════════╝""",
            "locations": ["desktop"]
        },
        "simulate_vssadmin": False,
        "simulate_persistence": True,
        "simulate_exfiltration": False,
        "simulate_network_beacon": False,
        "intensity_level": 1,
        "optional_delay_seconds": 0,
        "tags": ["MITRE:T1491", "MITRE:T1547", "TRAINING:BEGINNER"]
    },
    
    "wiper_sim": {
        "directories_to_target": ["C:\\RansomTest"],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf"],
        "rename_pattern": ".wiped",
        "ransom_note": {
            "filename": "WIPED.txt",
            "content": """DATA DESTRUCTION COMPLETE

All files have been permanently destroyed.
There is no recovery possible.
Your organization has been targeted.

--- RANSOMRUN WIPER SIMULATION ---
(Files moved to quarantine, not actually deleted)""",
            "locations": ["target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": False,
        "simulate_exfiltration": False,
        "simulate_network_beacon": False,
        "intensity_level": 3,
        "optional_delay_seconds": 2,
        "quarantine_mode": True,
        "tags": ["MITRE:T1485", "MITRE:T1490", "TRAINING:INTERMEDIATE"]
    },
    
    "exfil_only": {
        "directories_to_target": ["C:\\RansomTest"],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".csv"],
        "rename_pattern": "",
        "ransom_note": {
            "filename": "EXFIL_MARKER.txt",
            "content": """DATA EXFILTRATION MARKER

This file indicates that data exfiltration preparation was simulated.
The following actions were taken:
- Sensitive files identified
- Data compressed for staging
- Exfil path prepared

No actual data was transmitted.

--- RANSOMRUN EXFIL SIMULATION ---""",
            "locations": ["target_root"]
        },
        "simulate_vssadmin": False,
        "simulate_persistence": False,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "intensity_level": 2,
        "optional_delay_seconds": 3,
        "tags": ["MITRE:T1560", "MITRE:T1041", "TRAINING:INTERMEDIATE"]
    },
    
    "fake_ransom_training": {
        "directories_to_target": ["C:\\RansomTest"],
        "file_extensions": [".txt"],
        "rename_pattern": "",
        "ransom_note": {
            "filename": "TRAINING_ALERT.txt",
            "content": """╔═══════════════════════════════════════════════════════════╗
║              SECURITY AWARENESS TRAINING                    ║
╠═══════════════════════════════════════════════════════════╣
║                                                             ║
║  This is a SIMULATED ransomware attack for training.       ║
║                                                             ║
║  In a real attack, your files would be encrypted and       ║
║  you would be asked to pay a ransom.                       ║
║                                                             ║
║  REMEMBER:                                                  ║
║  - Never pay ransoms                                        ║
║  - Report suspicious emails to IT                           ║
║  - Keep backups of important files                          ║
║  - Don't click unknown links or attachments                 ║
║                                                             ║
║  --- RANSOMRUN TRAINING PLATFORM ---                        ║
╚═══════════════════════════════════════════════════════════╝""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": False,
        "simulate_persistence": False,
        "simulate_exfiltration": False,
        "simulate_network_beacon": False,
        "intensity_level": 1,
        "optional_delay_seconds": 0,
        "tags": ["TRAINING:BEGINNER", "AWARENESS"]
    },
    
    "multi_stage_combo": {
        "directories_to_target": ["C:\\RansomTest"],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf"],
        "rename_pattern": ".encrypted",
        "ransom_note": {
            "filename": "FINAL_WARNING.txt",
            "content": """MULTI-STAGE ATTACK COMPLETE

Stage 1: Persistence established
Stage 2: Files encrypted
Stage 3: Data prepared for exfiltration

Your organization has been fully compromised.
Pay 5.0 BTC to: 1MULTI2STAGE3SIM (NOT REAL)

--- RANSOMRUN MULTI-STAGE SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "intensity_level": 3,
        "optional_delay_seconds": 10,
        "stages": [
            {"name": "persistence", "delay": 3},
            {"name": "encryption", "delay": 5},
            {"name": "exfiltration", "delay": 2}
        ],
        "tags": ["MITRE:T1486", "MITRE:T1547", "MITRE:T1560", "TRAINING:ADVANCED"]
    },
    
    # =========================================================================
    # AGGRESSIVE RANSOMWARE SCENARIOS
    # =========================================================================
    
    "lockbit_sim": {
        "enable_gui_popup": True,
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents",
            "C:\\RansomLab"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".pptx", ".csv", ".json", ".xml", ".sql", ".bak", ".mdb"],
        "rename_pattern": ".lockbit3",
        "ransom_note": {
            "filename": "README-LOCKBIT.txt",
            "content": """~~~ LockBit 3.0 Ransomware ~~~

>>>> Your data is stolen and encrypted

The important files on your system have been ENCRYPTED and STOLEN.
If you don't pay the ransom, the data will be published on our TOR darknet sites.

>>>> What guarantees?
We are not a politically motivated group and we do not need anything other than your money.
Before paying you can send us up to 3 files for free decryption.

>>>> How to contact us?
Download and install TOR Browser: https://www.torproject.org/
Open our website: http://lockbit3xxxx.onion (SIMULATION)

>>>> Warning! Do not DELETE or MODIFY any files!

Personal ID: SIM-{random_id}
BTC Address: bc1qsimulation123 (NOT REAL)

--- RANSOMRUN LOCKBIT SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "intensity_level": 5,
        "optional_delay_seconds": 5,
        "wallpaper_change": True,
        "disable_recovery": True,
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1547", "MITRE:T1041", "TRAINING:EXPERT", "APT:LOCKBIT"]
    },
    
    "conti_sim": {
        "enable_gui_popup": True,
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".pptx", ".csv", ".json", ".xml", ".sql", ".bak"],
        "rename_pattern": ".CONTI",
        "ransom_note": {
            "filename": "readme.txt",
            "content": """All of your files are currently encrypted by CONTI ransomware.
If you try to use any additional recovery software - the files might be damaged or lost.

To make sure that we REALLY CAN recover data - we offer free decryption for 2 files.

You can find our contact information at the bottom of this note.

!!! DANGER !!!
DON'T try to change files by yourself, DON'T use any third party software.
It may damage your files permanently.

Contact us:
Email: conti_sim@ransomrun.local (SIMULATION)
TOX ID: SIMULATION_ONLY_NOT_REAL

--- RANSOMRUN CONTI SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "intensity_level": 5,
        "optional_delay_seconds": 3,
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1547", "TRAINING:EXPERT", "APT:CONTI"]
    },
    
    "blackcat_sim": {
        "enable_gui_popup": True,
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents",
            "C:\\RansomLab"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".pptx", ".csv", ".json", ".xml", ".sql", ".bak", ".vmdk", ".vhdx"],
        "rename_pattern": ".alphv",
        "ransom_note": {
            "filename": "RECOVER-alphv-FILES.txt",
            "content": """>> Introduction
Important files on your system were ENCRYPTED and now have "alphv" extension.
In order to recover your files you need to follow instructions below.

>> Sensitive Data
Sensitive data on your system was DOWNLOADED.
If you DON'T contact us - data will be published publicly and/or sold to third parties.

>> CAdistribution
DO NOT MODIFY ENCRYPTED FILES YOURSELF.
DO NOT USE THIRD PARTY SOFTWARE TO RESTORE YOUR DATA.
YOU MAY DAMAGE YOUR FILES, IT WILL RESULT IN PERMANENT DATA LOSS.

>> What to do?
1) Download TOR browser
2) Open http://alphvmmm27o3abo.onion (SIMULATION)
3) Enter your personal ID: SIM-BLACKCAT-{id}

--- RANSOMRUN BLACKCAT/ALPHV SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "intensity_level": 5,
        "optional_delay_seconds": 8,
        "cross_platform": True,
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1547", "MITRE:T1041", "TRAINING:EXPERT", "APT:BLACKCAT"]
    },
    
    "revil_sim": {
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".pptx", ".csv", ".json", ".xml"],
        "rename_pattern": ".revil",
        "ransom_note": {
            "filename": "{EXT}-readme.txt",
            "content": """---=== Welcome. Again. ===---

[+] What's Happened? [+]
Your files have been encrypted and currently unavailable.
You can check it: all files on your system have extension {EXT}.

[+] What does this mean? [+]
This means that the structure and data within your files have been irrevocably changed.

[+] What should I do? [+]
If you want to restore your files, you need to pay for decryption.
You can send 2 files for test decryption.

[+] How do I get access? [+]
You have two ways:
1) TOR Browser - http://aplebzu47wgazapdqks.onion (SIMULATION)
2) Normal Browser - http://decoder.re (SIMULATION)

--- RANSOMRUN REVIL/SODINOKIBI SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "intensity_level": 5,
        "optional_delay_seconds": 5,
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1547", "TRAINING:EXPERT", "APT:REVIL"]
    },
    
    "ryuk_sim": {
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".pptx", ".csv", ".bak", ".sql"],
        "rename_pattern": ".RYK",
        "ransom_note": {
            "filename": "RyukReadMe.txt",
            "content": """Gentlemen!

Your business is at serious risk.
There is a significant hole in the security system of your company.
We've easily penetrated your network.

You should thank the Lord for being hacked by serious people not some stupid schoolboys or dangerous punks.
They can damage all your important data just for fun.

Now your files are crypted with the strongest millitary algorithms RSA4096 and AES-256.
No one can help you to restore files without our special decoder.

Photorec, RannohDecryptor etc. repair tools are useless and can destroy your files irreversibly.

If you want to restore your files write to emails:
ryuk_sim@ransomrun.local (SIMULATION)

BTC wallet: bc1qryuksimulation (NOT REAL)

--- RANSOMRUN RYUK SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": False,
        "simulate_network_beacon": True,
        "intensity_level": 5,
        "optional_delay_seconds": 10,
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1547", "TRAINING:EXPERT", "APT:RYUK"]
    },
    
    "maze_sim": {
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".pptx", ".csv", ".json"],
        "rename_pattern": ".maze",
        "ransom_note": {
            "filename": "DECRYPT-FILES.txt",
            "content": """Attention!
---------------------------

All your documents, photos, databases and other important files have been encrypted!

The only method of recovering files is to purchase an unique private key.
Only we can give you this key and only we can recover your files.

We also downloaded a lot of private data from your network.
If you do not contact us in 3 days we will post information about your breach.

To get your private key and our contact:
1) Download TOR Browser
2) Go to http://mazexxxx.onion (SIMULATION)
3) Follow instructions

Your personal ID: MAZE-SIM-{id}

--- RANSOMRUN MAZE SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "intensity_level": 5,
        "optional_delay_seconds": 5,
        "double_extortion": True,
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1547", "MITRE:T1041", "TRAINING:EXPERT", "APT:MAZE"]
    },
    
    # =========================================================================
    # ADVANCED SIMULATION - POLYMORPHIC + CLOUD ATTACK
    # =========================================================================
    
    "advanced_polymorphic": {
        "enable_gui_popup": True,
        "directories_to_target": [
            "C:\\RansomTest",
            "C:\\Users\\Public\\Documents",
            "C:\\RansomLab"
        ],
        "file_extensions": [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png", ".csv", ".json", ".xml", ".sql", ".bak"],
        "rename_pattern": ".locked",
        "ransom_note": {
            "filename": "READ_ME_NOW.txt",
            "content": """YOUR FILES ARE ENCRYPTED!

This is a SIMULATION of an advanced polymorphic ransomware attack.

=== ATTACK CHAIN EXECUTED ===
[1] Polymorphic Dropper - Evaded hash-based detection
[2] VSS Tampering - Shadow copies targeted (T1490)
[3] Lateral Movement - Network spread attempted (T1021)
[4] File Encryption - Data encrypted for impact (T1486)
[5] Cloud Attack - S3/Cloud storage targeted (T1530)

=== RECOVERY ===
Simply rename your files back to remove '.locked' extension.

Pay 0 BTC to: SIMULATION_WALLET (NOT REAL)

--- RANSOMRUN ADVANCED SIMULATION ---""",
            "locations": ["desktop", "target_root"]
        },
        "simulate_vssadmin": True,
        "simulate_persistence": True,
        "simulate_exfiltration": True,
        "simulate_network_beacon": True,
        "simulate_lateral_movement": True,
        "simulate_cloud_attack": True,
        "polymorphic_mode": True,
        "intensity_level": 5,
        "optional_delay_seconds": 3,
        "stages": [
            {"name": "dropper", "delay": 2, "description": "Polymorphic payload generation"},
            {"name": "vss_tampering", "delay": 1, "description": "Shadow copy deletion"},
            {"name": "lateral_movement", "delay": 2, "description": "Network spread attempt"},
            {"name": "encryption", "delay": 3, "description": "File encryption"},
            {"name": "cloud_attack", "delay": 2, "description": "Cloud storage attack"}
        ],
        "mitre_techniques": ["T1486", "T1490", "T1021", "T1046", "T1530", "T1485", "T1027"],
        "tags": ["MITRE:T1486", "MITRE:T1490", "MITRE:T1021", "MITRE:T1530", "TRAINING:EXPERT", "APT:ADVANCED", "POLYMORPHIC"]
    }
}


def seed_scenarios(db: Session):
    """Seed default scenarios if they don't exist."""
    scenarios = [
        {
            "key": "crypto_basic",
            "name": "Basic Crypto Ransomware",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "Simulates basic crypto ransomware behavior:\n"
                "• Mass file rename (adds .locked extension)\n"
                "• Creates ransom note (README_RESTORE.txt)\n"
                "• Deletes shadow copies via vssadmin\n\n"
                "Target: C:\\RansomTest | Intensity: Low"
            ),
            "config": SCENARIO_CONFIGS["crypto_basic"]
        },
        {
            "key": "crypto_aggressive",
            "name": "Aggressive Crypto Ransomware",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "Simulates aggressive ransomware with multiple targets:\n"
                "• Targets multiple directories\n"
                "• High file count (200+ files)\n"
                "• Shadow copy deletion\n"
                "• Persistence mechanism\n"
                "• Network beacon simulation\n\n"
                "Target: Multiple dirs | Intensity: High"
            ),
            "config": SCENARIO_CONFIGS["crypto_aggressive"]
        },
        {
            "key": "locker_desktop",
            "name": "Desktop Locker",
            "category": ScenarioCategory.LOCKER,
            "description": (
                "Simulates screen locker ransomware:\n"
                "• Does NOT rename files\n"
                "• Drops lock screen message on desktop\n"
                "• Creates persistence registry key\n\n"
                "Target: Desktop only | Intensity: Minimal"
            ),
            "config": SCENARIO_CONFIGS["locker_desktop"]
        },
        {
            "key": "wiper_sim",
            "name": "Wiper Simulation",
            "category": ScenarioCategory.WIPER,
            "description": (
                "Simulates destructive wiper malware:\n"
                "• Moves files to quarantine folder\n"
                "• Logs files as 'wiped'\n"
                "• Shadow copy deletion\n"
                "• Files are NOT actually deleted\n\n"
                "Target: C:\\RansomTest | Intensity: Medium"
            ),
            "config": SCENARIO_CONFIGS["wiper_sim"]
        },
        {
            "key": "exfil_only",
            "name": "Data Exfiltration Only",
            "category": ScenarioCategory.EXFIL,
            "description": (
                "Simulates data exfiltration preparation:\n"
                "• Scans for sensitive file types\n"
                "• Compresses files to staging ZIP\n"
                "• NO actual network upload\n"
                "• Generates detection-worthy logs\n\n"
                "Target: C:\\RansomTest | Intensity: Low"
            ),
            "config": SCENARIO_CONFIGS["exfil_only"]
        },
        {
            "key": "fake_ransom_training",
            "name": "Training Mode (Fake Ransom)",
            "category": ScenarioCategory.FAKE,
            "description": (
                "Minimal impact training scenario:\n"
                "• Only drops educational ransom note\n"
                "• No file modifications\n"
                "• Perfect for awareness training\n\n"
                "Target: Desktop | Intensity: Minimal"
            ),
            "config": SCENARIO_CONFIGS["fake_ransom_training"]
        },
        {
            "key": "multi_stage_combo",
            "name": "Multi-Stage Attack",
            "category": ScenarioCategory.MULTI_STAGE,
            "description": (
                "Advanced multi-stage attack simulation:\n"
                "• Stage 1: Establish persistence\n"
                "• Stage 2: Encrypt files\n"
                "• Stage 3: Prepare exfiltration\n"
                "• Includes delays between stages\n\n"
                "Target: C:\\RansomTest | Intensity: High"
            ),
            "config": SCENARIO_CONFIGS["multi_stage_combo"]
        },
        # =========================================================================
        # AGGRESSIVE APT-STYLE RANSOMWARE SCENARIOS
        # =========================================================================
        {
            "key": "lockbit_sim",
            "name": "LockBit 3.0 Simulation",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "🔴 EXPERT: LockBit 3.0 APT simulation:\n"
                "• Double extortion (encrypt + steal)\n"
                "• Multiple directory targets\n"
                "• Shadow copy deletion\n"
                "• Persistence + network beacon\n"
                "• Wallpaper change simulation\n\n"
                "Target: Multiple dirs | Intensity: MAXIMUM"
            ),
            "config": SCENARIO_CONFIGS["lockbit_sim"]
        },
        {
            "key": "conti_sim",
            "name": "Conti Ransomware Simulation",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "🔴 EXPERT: Conti APT simulation:\n"
                "• Fast encryption simulation\n"
                "• Data exfiltration staging\n"
                "• Shadow copy deletion\n"
                "• Persistence mechanism\n\n"
                "Target: Multiple dirs | Intensity: MAXIMUM"
            ),
            "config": SCENARIO_CONFIGS["conti_sim"]
        },
        {
            "key": "blackcat_sim",
            "name": "BlackCat/ALPHV Simulation",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "🔴 EXPERT: BlackCat/ALPHV APT simulation:\n"
                "• Cross-platform ransomware style\n"
                "• Double extortion tactics\n"
                "• Targets VMs (.vmdk, .vhdx)\n"
                "• Full attack chain simulation\n\n"
                "Target: Multiple dirs | Intensity: MAXIMUM"
            ),
            "config": SCENARIO_CONFIGS["blackcat_sim"]
        },
        {
            "key": "revil_sim",
            "name": "REvil/Sodinokibi Simulation",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "🔴 EXPERT: REvil APT simulation:\n"
                "• RaaS-style attack pattern\n"
                "• Shadow copy deletion\n"
                "• Persistence + exfiltration\n"
                "• Network beacon simulation\n\n"
                "Target: Multiple dirs | Intensity: MAXIMUM"
            ),
            "config": SCENARIO_CONFIGS["revil_sim"]
        },
        {
            "key": "ryuk_sim",
            "name": "Ryuk Ransomware Simulation",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "🔴 EXPERT: Ryuk APT simulation:\n"
                "• Enterprise-targeted attack\n"
                "• High-value file targeting\n"
                "• Shadow copy deletion\n"
                "• Persistence mechanism\n\n"
                "Target: Multiple dirs | Intensity: MAXIMUM"
            ),
            "config": SCENARIO_CONFIGS["ryuk_sim"]
        },
        {
            "key": "maze_sim",
            "name": "Maze Ransomware Simulation",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "🔴 EXPERT: Maze APT simulation:\n"
                "• Pioneer of double extortion\n"
                "• Data theft + encryption\n"
                "• Public shaming threat\n"
                "• Full attack chain\n\n"
                "Target: Multiple dirs | Intensity: MAXIMUM"
            ),
            "config": SCENARIO_CONFIGS["maze_sim"]
        },
        {
            "key": "advanced_polymorphic",
            "name": "Advanced Polymorphic Attack",
            "category": ScenarioCategory.CRYPTO,
            "description": (
                "🔴 EXPERT: Advanced multi-stage polymorphic attack:\n"
                "• Polymorphic dropper (evades hash detection)\n"
                "• VSS shadow copy tampering (T1490)\n"
                "• Lateral movement simulation (T1021)\n"
                "• File encryption with .locked extension (T1486)\n"
                "• Cloud storage attack simulation (T1530)\n"
                "• Network discovery (T1046)\n\n"
                "MITRE: T1486, T1490, T1021, T1530, T1046, T1027\n"
                "Target: Multiple dirs | Intensity: MAXIMUM"
            ),
            "config": SCENARIO_CONFIGS["advanced_polymorphic"]
        }
    ]
    
    for s in scenarios:
        existing = crud.get_scenario_by_key(db, s["key"])
        if not existing:
            scenario = Scenario(
                key=s["key"],
                name=s["name"],
                description=s["description"],
                category=s.get("category", ScenarioCategory.CRYPTO),
                config=s.get("config"),
                is_custom=False,  # Built-in scenarios
                created_by="system"
            )
            db.add(scenario)
            db.commit()
            print(f"[SEED] Created scenario: {s['name']}")
        else:
            # Update existing scenario with new config if missing
            if existing.config is None and s.get("config"):
                existing.config = s["config"]
                existing.category = s.get("category", ScenarioCategory.CRYPTO)
                db.commit()
                print(f"[SEED] Updated scenario config: {s['name']}")
            # Ensure built-in scenarios are marked correctly
            if existing.is_custom is None or existing.is_custom:
                existing.is_custom = False
                existing.created_by = "system"
                db.commit()


# Old simple playbook seeding - replaced by comprehensive playbook seeding in seed_playbooks.py
# def seed_playbooks(db: Session):
#     """Seed default playbooks if they don't exist."""
#     # This function is now handled by app/seed_playbooks.py with advanced playbooks
#     pass


def run_seed(db: Session):
    """Run all seed functions."""
    print("[SEED] Starting database seeding...")
    seed_scenarios(db)
    # Note: Advanced playbooks are seeded separately in main.py startup
    
    # Seed business portal data
    try:
        from .seed_business import seed_business_user, seed_business_settings, seed_demo_organization, seed_pilot_config
        user = seed_business_user(db)
        seed_business_settings(db, user.id)
        seed_demo_organization(db)
        seed_pilot_config(db)
    except Exception as e:
        print(f"[SEED] Business portal seed warning: {e}")
    
    print("[SEED] Database seeding complete.")
