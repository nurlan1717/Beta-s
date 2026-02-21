# Ransomware Simulation Suite - Level 2/3

This suite mimics an advanced ransomware attack AND provides defensive tools for Blue Teams.

## 🛡️ Blue Team Defense (Run these FIRST)
1.  **`canary_defense.py`**:
    *   Creates hidden "Honeypot" files.
    *   **Action**: Open a terminal and run `python canary_defense.py`. Keep it running.
    *   **Goal**: Watch it trigger an ALERT when the ransomware encrypts the honeypots.
2.  **`entropy_monitor.py`**:
    *   **Action**: Open another terminal and run `python entropy_monitor.py`.
    *   **Goal**: Watch the graph. It starts at ~3-4 (Green). When ransomware hits, it spikes to ~7.9 (Red).

## ⚔️ Red Team Attack (Run these SECOND)
1.  **`ai_phishing.py`**: Generate the email.
2.  **`loader.py`**: Run the infection.
    *   The **WannaCry Screen** will appear.
    *   Files will be encrypted (Fernet).
    *   **CHECK YOUR BLUE TEAM TERMINALS**: You should see the Entropy Spike and Canary Alerts!

## 🚑 Recovery
1.  Click **"DECRYPT"** on the Red Screen or run `decrypter.py`.

## 🛠️ Setup
```bash
pip install -r requirements.txt
```
