import sys
import time
import os
import random

# Try to import boto3, but mock it if missing so the simulation still works
try:
    import boto3
    from botocore.exceptions import NoCredentialsError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

# --- CONFIGURATION ---
TARGET_BUCKET = "company-backups-critical"
# ---------------------

def log_cloud_mitre(tactic_id, description):
    print(f"\n[!] CLOUD ALERT: {tactic_id}: {description}")
    time.sleep(0.5)

def simulate_cloud_attack():
    print("=== STARTING CLOUD RANSOMWARE MODULE ===")
    
    # T1530: Data from Cloud Storage Object
    log_cloud_mitre("T1530", "Connecting to Cloud Storage (S3/MinIO)...")
    
    if not HAS_BOTO:
        print("[!] 'boto3' library not found. Running in SIMULATION MOCK MODE.")
        mock_cloud_attack()
        return

    # Real (or Local MinIO) Attack Logic
    s3 = boto3.client('s3')
    
    try:
        # List Buckets
        print(f"[*] Attempting to list contents of bucket: {TARGET_BUCKET}")
        # objects = s3.list_objects_v2(Bucket=TARGET_BUCKET) # Commented out to prevent accidental API calls if user runs it
        
        print("[-] AWS Credentials not found or Bucket does not exist (Safety Stop).")
        print("[*] Switching to Mock Mode for Demonstration...")
        mock_cloud_attack()
        
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        print("[*] Switching to Mock Mode...")
        mock_cloud_attack()

def mock_cloud_attack():
    """
    Simulates the attack steps without needing real AWS keys.
    """
    # Simulate Discovery
    fake_files = ["database_dump.sql", "ceo_emails.zip", "customer_list.csv", "financials_2025.xlsx"]
    print(f"[+] Connection Established to Bucket: s3://{TARGET_BUCKET}")
    print(f"[+] Found {len(fake_files)} critical objects.")
    
    for file in fake_files:
        print(f"\n[*] Processing: {file}")
        
        # T1565: Data Manipulation (Encrypting)
        time.sleep(0.5)
        print(f"    -> Downloading {file}...")
        
        # T1485: Data Destruction (Deleting original)
        log_cloud_mitre("T1485", "Data Encrypted for Impact (Cloud)")
        print(f"    -> Encrypting content (AES-256)...")
        print(f"    -> Uploading {file}.enc")
        print(f"    -> DELETING ORIGINAL {file}")
        
    print("\n[+] Cloud Attack Complete. All bucket files encrypted.")
    print(f"[!] Dropped Ransom Note to s3://{TARGET_BUCKET}/RESTORE_INSTRUCTIONS.txt")

if __name__ == "__main__":
    simulate_cloud_attack()
