# Testing GUI Ransomware Popup

## ✅ Setup Complete!

The GUI ransomware popup is now integrated into the agent and will automatically launch for advanced scenarios.

## How to Trigger the GUI Popup

### Method 1: Run Advanced Scenarios (Recommended)

The following scenarios will **automatically** show the GUI popup:

1. **LockBit 3.0 Simulation** (`lockbit_sim`)
2. **Conti Ransomware Simulation** (`conti_sim`)
3. **BlackCat/ALPHV Simulation** (`blackcat_sim`)
4. **Advanced Polymorphic Attack** (`advanced_polymorphic`)

**Steps:**
1. Start the agent on your victim VM:
   ```bash
   cd agent
   python agent.py --server http://192.168.10.100:8000
   ```

2. From the RansomRun dashboard, go to **Simulations**

3. Select one of the advanced scenarios (e.g., "LockBit 3.0 Simulation")

4. Click **"Start Simulation"**

5. **The GUI popup will appear automatically!** 🎯

### Method 2: Direct GUI Launch (Testing Only)

To test the GUI independently:

```bash
cd Advanced_Simulation
python wana_decrypt0r_gui.py
```

This will show the full-screen ransomware GUI immediately.

## What You'll See

When the GUI launches:

1. **Full-Screen Takeover** - Red/black interface fills the screen
2. **Lock Icon** - Pulsing red lock symbol (🔒)
3. **Payment Demand** - "$300 USD (Bitcoin)"
4. **Countdown Timer** - "72:00:00" time remaining
5. **Activity Log** - Real-time MITRE technique execution:
   - `[T1490]` VSS shadow copy deletion
   - `[T1021]` Lateral movement to network shares
   - `[T1486]` File encryption in progress
6. **Decrypt Button** - "I UNDERSTAND - RESTORE MY FILES"

## How to Exit/Decrypt

1. Click the **"I UNDERSTAND - RESTORE MY FILES (DECRYPT)"** button
2. Confirm you learned from the simulation
3. Files are automatically decrypted and restored
4. GUI closes

**Alternative:** Use Task Manager (Ctrl+Shift+Esc) to force-close Python process

## Behind the Scenes

When you run an advanced scenario:

1. **Agent receives task** from backend
2. **Agent checks** if `enable_gui_popup: True` in scenario config
3. **Agent launches** `wana_decrypt0r_gui.py` in separate process
4. **GUI appears** while agent continues encryption in background
5. **Both processes** work together for realistic simulation

## File Locations

```
Advanced_Simulation/
├── wana_decrypt0r_gui.py       # GUI ransomware (auto-launched)
├── target_data/                 # Files to be encrypted
│   ├── confidential_hr.xlsx
│   ├── q3_financials.pdf
│   ├── ceo_passwords.txt
│   └── network_map.png
└── encryption_key.key           # Generated during encryption
```

## Troubleshooting

### GUI Doesn't Appear
- ✅ Check agent logs for "Launching GUI ransomware popup..."
- ✅ Verify `Advanced_Simulation/wana_decrypt0r_gui.py` exists
- ✅ Ensure tkinter is installed: `python -m tkinter`
- ✅ Run GUI directly to test: `python wana_decrypt0r_gui.py`

### Files Not Encrypting
- ✅ Check `target_data/` directory exists
- ✅ Install cryptography: `pip install cryptography`
- ✅ Or run in simulation mode (automatic fallback)

### Agent Not Connecting
- ✅ Verify backend is running: http://192.168.10.100:8000
- ✅ Check firewall allows port 8000
- ✅ Confirm IP address in agent command

## Example: Full Workflow

```bash
# On Backend Server (192.168.10.100)
cd RansomRun
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# On Victim VM (192.168.10.68)
cd RansomRun\agent
python agent.py --server http://192.168.10.100:8000

# From Browser (Dashboard)
1. Navigate to http://192.168.10.100:8000
2. Go to Simulations
3. Select "LockBit 3.0 Simulation"
4. Click "Start Simulation"
5. Watch the GUI popup appear on victim VM! 🎯
```

## MITRE ATT&CK Techniques Demonstrated

| Technique | ID | Visual in GUI |
|-----------|-----|---------------|
| Data Encrypted for Impact | T1486 | Real-time file locking log |
| Inhibit System Recovery | T1490 | VSS deletion command shown |
| Remote Services | T1021 | Lateral movement to shares |
| User Execution | T1204 | GUI interaction required |

## Safety Notes

⚠️ **This is a training simulation!**

- Only encrypts files in `target_data/` directory
- Decryption key is saved locally
- No actual C2 communication
- No real damage to system
- Designed for educational purposes

---

**Ready to test?** Run an advanced scenario and watch the GUI popup appear! 🚀
