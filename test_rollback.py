"""
AutoRollback Test Script

This script provides test stubs and manual test functions for the AutoRollback feature.
Run this script to validate the rollback functionality in your lab environment.

Usage:
    python test_rollback.py setup       # Create test files
    python test_rollback.py encrypt     # Simulate ransomware (rename files)
    python test_rollback.py verify      # Verify file states
    python test_rollback.py cleanup     # Remove test files
"""

import os
import sys
import hashlib
import shutil
from pathlib import Path
from datetime import datetime

# Test configuration
TEST_DIR = r"C:\RansomTest"
BACKUP_DIR = r"C:\RansomTest\.backup"
RANSOMWARE_EXT = ".locked"

# Test files to create
TEST_FILES = [
    ("financial_report_2025.txt", "CONFIDENTIAL FINANCIAL REPORT\n" + "="*50 + "\nRevenue: $1,250,000\nExpenses: $890,000\nProfit: $360,000"),
    ("employee_database.csv", "ID,Name,Department,Salary\n1,John Smith,Engineering,85000\n2,Jane Doe,Marketing,78000\n3,Bob Wilson,Sales,72000"),
    ("client_contracts.txt", "CLIENT CONTRACTS - CONFIDENTIAL\n" + "="*50 + "\nABC Corp: $500,000\nXYZ Inc: $350,000\nAcme Ltd: $275,000"),
    ("project_secrets.txt", "PROJECT PHOENIX - TOP SECRET\n" + "="*50 + "\nLaunch Date: Q2 2025\nBudget: $2.5M\nKey Partners: TBD"),
    ("passwords.txt", "SYSTEM PASSWORDS\n" + "="*50 + "\nAdmin: P@ssw0rd123\nDatabase: DbSecure456\nVPN: VpnAccess789"),
]


def compute_hash(filepath: str) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def setup_test_environment():
    """Create test directory and files."""
    print(f"\n[SETUP] Creating test environment in {TEST_DIR}")
    print("="*60)
    
    # Create directories
    os.makedirs(TEST_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # Create test files
    for filename, content in TEST_FILES:
        filepath = os.path.join(TEST_DIR, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        
        # Create backup copy
        backup_path = os.path.join(BACKUP_DIR, filename)
        shutil.copy2(filepath, backup_path)
        
        file_hash = compute_hash(filepath)
        print(f"  [+] Created: {filename}")
        print(f"      Hash: {file_hash[:16]}...")
    
    print(f"\n[OK] Created {len(TEST_FILES)} test files")
    print(f"[OK] Backup copies stored in {BACKUP_DIR}")
    
    # Create manifest file
    manifest_path = os.path.join(BACKUP_DIR, "manifest.txt")
    with open(manifest_path, 'w') as f:
        f.write(f"Backup Manifest - {datetime.now().isoformat()}\n")
        f.write("="*60 + "\n")
        for filename, _ in TEST_FILES:
            filepath = os.path.join(TEST_DIR, filename)
            file_hash = compute_hash(filepath)
            f.write(f"{filename}|{file_hash}\n")
    
    print(f"[OK] Manifest created: {manifest_path}")


def simulate_ransomware():
    """Simulate ransomware by renaming files with .locked extension."""
    print(f"\n[ATTACK] Simulating ransomware in {TEST_DIR}")
    print("="*60)
    
    if not os.path.exists(TEST_DIR):
        print("[ERROR] Test directory not found. Run 'setup' first.")
        return
    
    encrypted_count = 0
    for filename, _ in TEST_FILES:
        filepath = os.path.join(TEST_DIR, filename)
        locked_path = filepath + RANSOMWARE_EXT
        
        if os.path.exists(filepath):
            os.rename(filepath, locked_path)
            print(f"  [!] ENCRYPTED: {filename} -> {filename}{RANSOMWARE_EXT}")
            encrypted_count += 1
        elif os.path.exists(locked_path):
            print(f"  [~] Already encrypted: {filename}{RANSOMWARE_EXT}")
    
    # Create ransom note
    ransom_note = os.path.join(TEST_DIR, "!!!READ_ME!!!.txt")
    with open(ransom_note, 'w') as f:
        f.write("""
================================================================================
                    YOUR FILES HAVE BEEN ENCRYPTED!
================================================================================

All your important files have been encrypted with military-grade encryption.

To recover your files, you must pay the ransom.

This is a SIMULATION for security training purposes.

To restore your files, use the AutoRollback feature in RansomRun.

================================================================================
""")
    
    print(f"\n[!] Encrypted {encrypted_count} files")
    print(f"[!] Ransom note created: {ransom_note}")


def verify_file_states():
    """Verify the current state of test files."""
    print(f"\n[VERIFY] Checking file states in {TEST_DIR}")
    print("="*60)
    
    if not os.path.exists(TEST_DIR):
        print("[ERROR] Test directory not found.")
        return
    
    original_count = 0
    encrypted_count = 0
    missing_count = 0
    
    for filename, expected_content in TEST_FILES:
        filepath = os.path.join(TEST_DIR, filename)
        locked_path = filepath + RANSOMWARE_EXT
        backup_path = os.path.join(BACKUP_DIR, filename)
        
        if os.path.exists(filepath):
            # Original file exists
            current_hash = compute_hash(filepath)
            
            # Check if content matches original
            with open(filepath, 'r') as f:
                current_content = f.read()
            
            if current_content == expected_content:
                print(f"  [OK] {filename} - Original (verified)")
                original_count += 1
            else:
                print(f"  [?] {filename} - Modified")
                original_count += 1
                
        elif os.path.exists(locked_path):
            print(f"  [!] {filename} - ENCRYPTED ({RANSOMWARE_EXT})")
            encrypted_count += 1
        else:
            print(f"  [X] {filename} - MISSING")
            missing_count += 1
    
    print(f"\n[SUMMARY]")
    print(f"  Original files: {original_count}")
    print(f"  Encrypted files: {encrypted_count}")
    print(f"  Missing files: {missing_count}")
    
    # Check backup status
    if os.path.exists(BACKUP_DIR):
        backup_files = [f for f in os.listdir(BACKUP_DIR) if not f.startswith('.') and f != 'manifest.txt']
        print(f"  Backup files available: {len(backup_files)}")


def cleanup_test_environment():
    """Remove test files and directories."""
    print(f"\n[CLEANUP] Removing test environment")
    print("="*60)
    
    if os.path.exists(TEST_DIR):
        # Remove all files
        for item in os.listdir(TEST_DIR):
            item_path = os.path.join(TEST_DIR, item)
            if os.path.isfile(item_path):
                os.remove(item_path)
                print(f"  [-] Removed: {item}")
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
                print(f"  [-] Removed directory: {item}")
        
        print(f"\n[OK] Cleaned up {TEST_DIR}")
    else:
        print("[INFO] Test directory doesn't exist")


def manual_restore():
    """Manually restore files from backup (simulates rollback)."""
    print(f"\n[RESTORE] Restoring files from backup")
    print("="*60)
    
    if not os.path.exists(BACKUP_DIR):
        print("[ERROR] Backup directory not found.")
        return
    
    restored_count = 0
    
    for filename, _ in TEST_FILES:
        backup_path = os.path.join(BACKUP_DIR, filename)
        target_path = os.path.join(TEST_DIR, filename)
        locked_path = target_path + RANSOMWARE_EXT
        
        if not os.path.exists(backup_path):
            print(f"  [X] No backup for: {filename}")
            continue
        
        # Remove encrypted version if exists
        if os.path.exists(locked_path):
            os.remove(locked_path)
        
        # Restore from backup
        shutil.copy2(backup_path, target_path)
        
        # Verify
        backup_hash = compute_hash(backup_path)
        restored_hash = compute_hash(target_path)
        
        if backup_hash == restored_hash:
            print(f"  [OK] Restored: {filename} (hash verified)")
            restored_count += 1
        else:
            print(f"  [!] Restored: {filename} (hash mismatch!)")
    
    # Remove ransom note
    ransom_note = os.path.join(TEST_DIR, "!!!READ_ME!!!.txt")
    if os.path.exists(ransom_note):
        os.remove(ransom_note)
        print(f"  [-] Removed ransom note")
    
    print(f"\n[OK] Restored {restored_count} files")


def print_usage():
    """Print usage information."""
    print("""
AutoRollback Test Script
========================

Usage:
    python test_rollback.py <command>

Commands:
    setup       Create test directory and files with backups
    encrypt     Simulate ransomware (rename files to .locked)
    verify      Check current state of test files
    restore     Manually restore files from backup
    cleanup     Remove all test files and directories

Demo Flow:
    1. python test_rollback.py setup     # Create test files
    2. python test_rollback.py verify    # Verify original state
    3. Create backup snapshot via RansomRun API or UI
    4. python test_rollback.py encrypt   # Simulate attack
    5. python test_rollback.py verify    # Verify encrypted state
    6. Create rollback plan via RansomRun API or UI
    7. Approve and execute rollback
    8. python test_rollback.py verify    # Verify restored state

API Commands:
    # Create backup snapshot
    curl -X POST http://localhost:8000/api/backup/snapshot/1
    
    # Create rollback plan (dry run)
    curl -X POST http://localhost:8000/api/rollback/plan \\
        -H "Content-Type: application/json" \\
        -d '{"host_id": 1, "dry_run": true}'
    
    # Create rollback plan (real)
    curl -X POST http://localhost:8000/api/rollback/plan \\
        -H "Content-Type: application/json" \\
        -d '{"host_id": 1, "require_approval": true}'
    
    # Approve plan
    curl -X POST http://localhost:8000/api/rollback/plan/{plan_id}/approve
    
    # Execute plan
    curl -X POST http://localhost:8000/api/rollback/execute/{plan_id}
    
    # View report
    curl http://localhost:8000/api/rollback/reports/{plan_id}
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command == "setup":
        setup_test_environment()
    elif command == "encrypt":
        simulate_ransomware()
    elif command == "verify":
        verify_file_states()
    elif command == "restore":
        manual_restore()
    elif command == "cleanup":
        cleanup_test_environment()
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)
