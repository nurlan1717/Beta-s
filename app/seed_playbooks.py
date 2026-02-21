"""Seed advanced ransomware response playbooks."""

from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Playbook, PlaybookAction


def seed_playbooks(db: Session):
    """Seed 10+ advanced playbooks with MITRE mappings."""
    
    playbooks_data = [
        {
            "code": "PB-01",
            "name": "Ransomware Process + Shadow Delete Combo",
            "description": "Responds to VSS/shadow copy deletion attempts combined with suspicious process activity",
            "trigger_rule_id": "RR-2002",
            "severity_threshold": 7,
            "mitre_techniques": ["T1490", "T1486", "T1059"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "kill_process", "parameters": {"process_name": "vssadmin.exe"}, "description": "Terminate VSS admin process"},
                {"order": 2, "action_type": "kill_process", "parameters": {"process_name": "powershell.exe"}, "description": "Terminate PowerShell process"},
                {"order": 3, "action_type": "backup_snapshot", "parameters": {"snapshot_type": "FILE_LEVEL"}, "description": "Create emergency backup snapshot"},
                {"order": 4, "action_type": "isolate_host", "parameters": {"policy": "HYBRID", "ttl_minutes": 60}, "description": "Isolate host with 60-minute TTL"},
                {"order": 5, "action_type": "collect_triage", "parameters": {"triage_type": "ransomware_full"}, "description": "Collect full ransomware triage data"},
            ]
        },
        {
            "code": "PB-02",
            "name": "Mass File Rename / Encrypt Spike",
            "description": "Responds to rapid file encryption or mass file rename events",
            "trigger_rule_id": "RR-2001",
            "severity_threshold": 8,
            "mitre_techniques": ["T1486"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "isolate_host", "parameters": {"policy": "FIREWALL_BLOCK"}, "description": "Immediately isolate host with firewall block"},
                {"order": 2, "action_type": "kill_process", "parameters": {"process_name": "suspicious.exe"}, "description": "Kill suspicious encryption process"},
                {"order": 3, "action_type": "backup_snapshot", "parameters": {"snapshot_type": "FILE_LEVEL"}, "description": "Create backup of remaining files"},
                {"order": 4, "action_type": "collect_triage", "parameters": {"triage_type": "file_system"}, "description": "Collect file system forensics"},
                {"order": 5, "action_type": "protect_backup_targets", "parameters": {"backup_paths": ["C:\\Backups"]}, "description": "Protect backup directories"},
            ]
        },
        {
            "code": "PB-03",
            "name": "Ransom Note Creation",
            "description": "Responds to ransom note file creation (README.txt, HOW_TO_DECRYPT, etc.)",
            "trigger_rule_id": "RR-2103",
            "severity_threshold": 9,
            "mitre_techniques": ["T1486"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "isolate_host", "parameters": {"policy": "HYBRID", "ttl_minutes": 120}, "description": "Isolate host for 2 hours"},
                {"order": 2, "action_type": "backup_snapshot", "parameters": {"snapshot_type": "FILE_LEVEL"}, "description": "Emergency backup snapshot"},
                {"order": 3, "action_type": "collect_triage", "parameters": {"triage_type": "ransom_note_analysis"}, "description": "Collect ransom note and file list"},
                {"order": 4, "action_type": "escalate_alert", "parameters": {"severity_increase": 2}, "description": "Escalate alert severity"},
                {"order": 5, "action_type": "create_incident", "parameters": {"priority": "critical"}, "description": "Create critical incident record"},
            ]
        },
        {
            "code": "PB-04",
            "name": "Office -> Script -> Network (Initial Access)",
            "description": "Responds to Office document spawning script that makes network connections",
            "trigger_rule_id": "RR-2003",
            "severity_threshold": 6,
            "mitre_techniques": ["T1566", "T1059", "T1105"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "kill_process", "parameters": {"process_name": "powershell.exe"}, "description": "Kill PowerShell child process"},
                {"order": 2, "action_type": "kill_process", "parameters": {"process_name": "wscript.exe"}, "description": "Kill WScript process"},
                {"order": 3, "action_type": "isolate_host", "parameters": {"policy": "OUTBOUND_ONLY_BLOCK"}, "description": "Block outbound connections"},
                {"order": 4, "action_type": "block_ip", "parameters": {"ip_address": "auto_detect", "direction": "outbound"}, "description": "Block C2 IP address"},
                {"order": 5, "action_type": "collect_triage", "parameters": {"triage_type": "email_artifacts"}, "description": "Collect email and attachment artifacts"},
            ]
        },
        {
            "code": "PB-05",
            "name": "LSASS Access / Credential Dump",
            "description": "Responds to LSASS memory access or credential dumping attempts",
            "trigger_rule_id": "RR-2004",
            "severity_threshold": 8,
            "mitre_techniques": ["T1003.001"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "isolate_host", "parameters": {"policy": "HYBRID"}, "description": "Isolate compromised host"},
                {"order": 2, "action_type": "kill_process", "parameters": {"process_name": "mimikatz.exe"}, "description": "Kill credential dumping tool"},
                {"order": 3, "action_type": "disable_user", "parameters": {"username": "compromised_user"}, "description": "Disable compromised user account"},
                {"order": 4, "action_type": "collect_triage", "parameters": {"triage_type": "credential_theft"}, "description": "Collect credential theft forensics"},
                {"order": 5, "action_type": "escalate_alert", "parameters": {"severity_increase": 2}, "description": "Escalate to security team"},
            ]
        },
        {
            "code": "PB-06",
            "name": "Persistence Established",
            "description": "Responds to registry run key or startup folder persistence mechanisms",
            "trigger_rule_id": "RR-2201",
            "severity_threshold": 5,
            "mitre_techniques": ["T1547.001"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "kill_process", "parameters": {"process_name": "malware.exe"}, "description": "Kill malicious process"},
                {"order": 2, "action_type": "isolate_host", "parameters": {"policy": "OUTBOUND_ONLY_BLOCK", "ttl_minutes": 30}, "description": "Temporary outbound isolation"},
                {"order": 3, "action_type": "collect_triage", "parameters": {"triage_type": "autoruns_snapshot"}, "description": "Collect autoruns and persistence artifacts"},
            ]
        },
        {
            "code": "PB-07",
            "name": "Defense Evasion / Security Tool Tampering",
            "description": "Responds to attempts to disable AV/EDR or firewall",
            "trigger_rule_id": "RR-2202",
            "severity_threshold": 7,
            "mitre_techniques": ["T1562"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "isolate_host", "parameters": {"policy": "HYBRID"}, "description": "Isolate to prevent further tampering"},
                {"order": 2, "action_type": "kill_process", "parameters": {"process_name": "attacker_tool.exe"}, "description": "Kill tampering tool"},
                {"order": 3, "action_type": "collect_triage", "parameters": {"triage_type": "security_tools_status"}, "description": "Collect security tool status"},
            ]
        },
        {
            "code": "PB-08",
            "name": "Remote Services / Lateral Movement",
            "description": "Responds to PsExec, WMI, or WinRM lateral movement patterns",
            "trigger_rule_id": "RR-2301",
            "severity_threshold": 7,
            "mitre_techniques": ["T1021", "T1047"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "isolate_host", "parameters": {"policy": "SEGMENT_QUARANTINE_SIM"}, "description": "Quarantine to prevent lateral spread"},
                {"order": 2, "action_type": "block_ip", "parameters": {"direction": "inbound", "port": "445,135,5985"}, "description": "Block remote admin ports"},
                {"order": 3, "action_type": "collect_triage", "parameters": {"triage_type": "logon_events"}, "description": "Collect logon and authentication events"},
            ]
        },
        {
            "code": "PB-09",
            "name": "Data Exfil Prep",
            "description": "Responds to large archive creation with network activity (staging for exfil)",
            "trigger_rule_id": "RR-2401",
            "severity_threshold": 6,
            "mitre_techniques": ["T1560", "T1041"],
            "enabled": True,
            "requires_approval": False,
            "actions": [
                {"order": 1, "action_type": "block_ip", "parameters": {"ip_address": "auto_detect", "direction": "outbound"}, "description": "Block exfil destination"},
                {"order": 2, "action_type": "isolate_host", "parameters": {"policy": "OUTBOUND_ONLY_BLOCK"}, "description": "Block all outbound traffic"},
                {"order": 3, "action_type": "collect_triage", "parameters": {"triage_type": "staged_archives"}, "description": "Collect staged archive paths and metadata"},
            ]
        },
        {
            "code": "PB-10",
            "name": "High Confidence Ransomware (Multi-signal)",
            "description": "Responds to correlation of multiple ransomware indicators",
            "trigger_rule_id": "RR-2999",
            "severity_threshold": 9,
            "mitre_techniques": ["T1486", "T1490", "T1562", "T1059"],
            "enabled": True,
            "requires_approval": True,
            "actions": [
                {"order": 1, "action_type": "backup_snapshot", "parameters": {"snapshot_type": "FILE_LEVEL"}, "requires_approval": False, "description": "Emergency backup (auto-approved)"},
                {"order": 2, "action_type": "isolate_host", "parameters": {"policy": "HYBRID", "ttl_minutes": 240}, "requires_approval": True, "description": "Long-term isolation (requires approval)"},
                {"order": 3, "action_type": "kill_process", "parameters": {"process_name": "all_suspicious"}, "requires_approval": False, "description": "Kill all suspicious processes"},
                {"order": 4, "action_type": "collect_triage", "parameters": {"triage_type": "full_incident_bundle"}, "requires_approval": False, "description": "Full forensic collection"},
                {"order": 5, "action_type": "create_incident", "parameters": {"priority": "critical", "auto_escalate": True}, "requires_approval": False, "description": "Create and escalate critical incident"},
            ]
        },
    ]
    
    print("\n" + "="*60)
    print("  SEEDING ADVANCED PLAYBOOKS")
    print("="*60)
    
    for pb_data in playbooks_data:
        # Check if playbook already exists
        existing = db.query(Playbook).filter(Playbook.code == pb_data["code"]).first()
        if existing:
            print(f"  [SKIP] {pb_data['code']}: {pb_data['name']} (already exists)")
            continue
        
        # Create playbook
        actions_data = pb_data.pop("actions")
        playbook = Playbook(**pb_data, created_by="system")
        db.add(playbook)
        db.flush()
        
        # Create actions
        for action_data in actions_data:
            action = PlaybookAction(playbook_id=playbook.id, **action_data)
            db.add(action)
        
        print(f"  [OK] {pb_data['code']}: {pb_data['name']}")
    
    db.commit()
    print("="*60)
    print(f"  [SUCCESS] Playbook seeding complete!")
    print("="*60 + "\n")


if __name__ == "__main__":
    db = SessionLocal()
    try:
        seed_playbooks(db)
    finally:
        db.close()
