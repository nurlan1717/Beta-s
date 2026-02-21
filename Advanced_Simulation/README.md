# Ransomware Simulation Suite - Level 2/3

This suite mimics an advanced ransomware attack with three components: a polymorphic dropper, a main payload, and a cloud attack module.

## 📂 Files
1.  **`loader.py`** (The Dropper): **Run this first.** It builds a unique payload to evade hash-based detection.
2.  **`ransomware_template.py`** (The Template): The clean source code of the ransomware. **Do not run this directly** unless debugging. The loader reads this.
3.  **`cloud_wiper.py`** (Cloud Module): A standalone script simulating an attack on S3/MinIO buckets.

## 🚀 How to Run (The Attack Flow)

### Step 1: Endpoint Attack (The Phishing Scenario)
1.  Open your terminal in this folder.
2.  Run the **Dropper**:
    ```bash
    python loader.py
    ```
3.  **What happens:**
    *   The dropper reads `ransomware_template.py`.
    *   It adds random "junk code" to change the file hash (Polymorphism).
    *   It creates a new file called `svc_host_update.py` (The Payload).
    *   It automatically runs `svc_host_update.py`.
4.  **The Payload Actions:**
    *   **MITRE Logging**: You will see logs like `[MITRE ATT&CK] T1486`.
    *   **VSS Tampering**: It tries to run `vssadmin list shadows`.
    *   **Lateral Movement**: It creates a file called `hacked_lateral.txt` in the parent directory to prove it could spread.
    *   **Encryption**: It creates a folder `target_data` (if missing), creates dummy files, and renames them to `.locked`.

### Step 2: Cloud Attack (Modern Scenario)
1.  Run the cloud module:
    ```bash
    python cloud_wiper.py
    ```
2.  **What happens:**
    *   It simulates connecting to an S3 bucket.
    *   It "downloads, encrypts, and deletes" files (Simulated/Mocked).
    *   If you have `boto3` installed and AWS keys, you can uncomment the code to make it real (USE WITH CAUTION).

## ⚠️ Safety Note
*   This simulation relies on **renaming files** (`.locked`) rather than actual strong encryption, so you can easily restore them.
*   **Target Directory**: It only affects files inside the `target_data` folder created in this directory.
*   **Lateral Movement**: It only writes a text file; it does not exploit vulnerabilities.
