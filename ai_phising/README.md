# Ransomware Simulation Suite - Level 2/3

This suite mimics an advanced ransomware attack with three components: a polymorphic dropper, a main payload, and a cloud attack module.
**NOW WITH: Real Encryption, Awareness Dashboard & AI Phishing**

## 📂 Files
1.  **`ai_phishing.py`** (The Hook): **Start Here.** Generates a believable email using AI to trick users into downloading the loader.
2.  **`loader.py`** (The Dropper): **The Attachment.** It builds a unique payload to evade hash-based detection.
3.  **`ransomware_template.py`** (The Payload): Contains the logic for encryption, MITRE logging, and the **Red Screen**.
4.  **`decrypter.py`** (The Rescue Tool): Run this to restore your files.
5.  **`cloud_wiper.py`** (Cloud Module): A standalone script simulating an attack on S3/MinIO buckets.

## 🛠️ Setup
Install dependencies:
```bash
pip install -r requirements.txt
```

## 🚀 How to Run (The Full Kill Chain)

### Step 1: Phishing (The Entry Vector)
1.  Run the AI Generator:
    ```bash
    python ai_phishing.py
    ```
2.  Enter your Gemini API Key and target details (e.g., "Finance Company").
3.  Copy the generated email. Send it to your test user (or yourself) with `loader.py` attached (rename it to something like `Invoice_Updater.py` or `.exe`).

### Step 2: Infection
1.  User clicks/runs the attachment (`loader.py`).
2.  **Polymorphism**: The dropper creates a unique `svc_host_update.py`.
3.  **Encryption**: It finds files in `target_data`, **encrypts** them, and saves a key (`encryption_key.key`).
4.  **Awareness Screen**: A Red Window pops up.

### Step 3: Recovery
1.  Run the **Decrypter**:
    ```bash
    python decrypter.py
    ```

### Step 4: Cloud Attack (Optional)
1.  Run the cloud module:
    ```bash
    python cloud_wiper.py
    ```

## ⚠️ Safety Note
*   **Target Directory**: Only affects `target_data`.
*   **Key File**: Do NOT delete `encryption_key.key`.
