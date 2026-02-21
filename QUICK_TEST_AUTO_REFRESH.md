# Quick Test Guide - ELK Auto-Refresh Feature

## 🚀 Quick Start (5 Minutes)

### Step 1: Start Backend Server
```powershell
cd "C:\Users\Student\OneDrive - Innovation and Digital Development Agency\Desktop\RansomRun"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Step 2: Open Dashboard
- URL: `http://localhost:8000/elk-dashboard`
- Or from network: `http://192.168.10.55:8000/elk-dashboard`

### Step 3: Test Auto-Refresh
1. ✅ Check the **"Auto Refresh"** toggle
2. ✅ Select **"5s"** from interval dropdown
3. ✅ Watch **"Last updated: HH:MM:SS"** change every 5 seconds
4. ✅ Open DevTools (F12) → Console to see logs: `Auto-refresh started: 5s interval`

### Step 4: Test Persistence
1. ✅ Change interval to **"30s"**
2. ✅ Press **F5** to refresh browser
3. ✅ Verify toggle is still checked and interval is 30s

### Step 5: Test Error Handling
1. ✅ Stop Elasticsearch (if running) or disconnect network
2. ✅ Watch status badge turn red: **"Disconnected"**
3. ✅ See error message appear in red below "Last updated"
4. ✅ After 3 failures, interval doubles (check console)

---

## 🎯 Test New Agent Playbooks

### Scenario 1: Credential Dump
```powershell
# On Windows agent machine
cd C:\RansomRun\agent
python agent.py
```

Then create a task via Web UI with config:
```json
{
  "simulate_credential_dump": true
}
```

**Expected Results:**
- File created: `C:\RansomTest\ExfilStaging\lsass_dump.dmp`
- Files created: `browser_passwords.txt`, `wifi_credentials.txt`, `saved_passwords.db`
- Dashboard shows alerts for T1003.001, T1003.002, T1552

### Scenario 2: Registry Persistence
Config:
```json
{
  "simulate_registry_persistence": true
}
```

**Expected Results:**
- IOCs logged for registry run keys
- Service creation logged: `WindowsSecurityService`
- Scheduled task logged: `SystemMaintenanceTask`
- Dashboard shows alerts for T1547.001, T1543.003, T1053.005

### Scenario 3: Process Injection
Config:
```json
{
  "simulate_process_injection": true
}
```

**Expected Results:**
- Process hollowing targets logged: svchost.exe, explorer.exe, notepad.exe
- DLL injection logged: `C:\Windows\Temp\payload.dll`
- Dashboard shows alerts for T1055.012, T1055.001, T1620

### Scenario 4: Defense Evasion
Config:
```json
{
  "simulate_defense_evasion": true
}
```

**Expected Results:**
- Log clearing events: Security, System, Application, Sysmon
- Timestomping logged
- Security tool tampering logged: Defender, Sysmon, Firewall
- Dashboard shows alerts for T1070.001, T1070.006, T1562.001

### Scenario 5: Full APT Chain (All Playbooks)
Config:
```json
{
  "simulate_vssadmin": true,
  "simulate_persistence": true,
  "simulate_exfiltration": true,
  "simulate_lateral_movement": true,
  "simulate_cloud_attack": true,
  "polymorphic_mode": true,
  "simulate_credential_dump": true,
  "simulate_registry_persistence": true,
  "simulate_process_injection": true,
  "simulate_defense_evasion": true,
  "file_extensions": [".txt", ".docx", ".xlsx"],
  "rename_pattern": ".locked",
  "ransom_note": {
    "filename": "README_RESTORE.txt",
    "content": "Your files have been encrypted! Contact us for decryption.",
    "locations": ["target_root", "desktop"]
  }
}
```

**Expected Results:**
- 15+ different MITRE techniques triggered
- 50+ IOCs generated
- 100+ events logged
- Dashboard MITRE heatmap shows full coverage

---

## ✅ Verification Checklist

### UI Components
- [ ] Auto-refresh toggle visible
- [ ] Interval dropdown shows: 5s, 10s, 30s, 60s
- [ ] "Last updated: HH:MM:SS" label visible
- [ ] Manual "Refresh" button works
- [ ] Error message appears when ES is down

### Functionality
- [ ] Toggle enables/disables auto-refresh
- [ ] Interval change restarts timer
- [ ] Manual refresh updates timestamp
- [ ] Settings persist after browser refresh
- [ ] No overlapping refresh requests (check console)

### Data Updates
- [ ] Connection status badge updates
- [ ] Stats cards update (Total Endpoints, Active Endpoints, etc.)
- [ ] Recent Alerts table updates
- [ ] Endpoints list updates
- [ ] MITRE heatmap updates

### Error Handling
- [ ] Disconnected state shows correctly
- [ ] Error message displays
- [ ] Backoff strategy activates after 3 failures
- [ ] Interval doubles on backoff (max 60s)
- [ ] Normal interval restored on success

### Agent Playbooks
- [ ] CREDENTIAL_DUMP creates LSASS dump file
- [ ] REGISTRY_PERSISTENCE logs registry IOCs
- [ ] PROCESS_INJECTION logs process targets
- [ ] DEFENSE_EVASION logs evasion techniques
- [ ] All IOCs appear in dashboard
- [ ] MITRE techniques mapped correctly

---

## 🐛 Common Issues & Fixes

### Issue: Auto-refresh not starting
**Fix:** 
```javascript
// Open browser console (F12) and run:
localStorage.clear();
location.reload();
```

### Issue: "Last updated" not changing
**Fix:** Check console for errors, verify backend is running

### Issue: High CPU usage
**Fix:** Increase interval to 30s or 60s

### Issue: Agent playbooks not creating files
**Fix:** 
- Ensure `C:\RansomTest` directory exists
- Run agent as Administrator
- Check agent.log for errors

### Issue: Dashboard shows "Disconnected"
**Fix:**
- Verify Elasticsearch is running: `http://localhost:9200`
- Check backend logs
- Verify SIEM_MODE environment variable

---

## 📊 Expected Performance

### Refresh Intervals
- **5s**: ~12 refreshes/minute, ~720/hour
- **10s**: ~6 refreshes/minute, ~360/hour
- **30s**: ~2 refreshes/minute, ~120/hour
- **60s**: ~1 refresh/minute, ~60/hour

### API Calls Per Refresh
- 5 endpoints called
- Total: 5 × refresh rate

### Network Traffic
- ~10-50 KB per refresh (depends on data volume)
- At 10s interval: ~300-3000 KB/minute

---

## 🎓 Learning Objectives

After testing, you should understand:
1. ✅ How auto-refresh improves SIEM usability
2. ✅ localStorage for persisting user preferences
3. ✅ AJAX for partial page updates
4. ✅ Error handling and backoff strategies
5. ✅ MITRE ATT&CK framework coverage
6. ✅ Credential dumping techniques (T1003)
7. ✅ Persistence mechanisms (T1547, T1543, T1053)
8. ✅ Process injection methods (T1055)
9. ✅ Defense evasion tactics (T1070, T1562)

---

## 📝 Test Report Template

```
=== ELK Auto-Refresh Test Report ===
Date: _______________
Tester: _______________

[ ] Auto-refresh toggle works
[ ] Interval selection works (5s, 10s, 30s, 60s)
[ ] Last updated timestamp updates
[ ] Settings persist after browser refresh
[ ] Error handling works (backoff strategy)
[ ] Manual refresh button works

[ ] CREDENTIAL_DUMP playbook tested
[ ] REGISTRY_PERSISTENCE playbook tested
[ ] PROCESS_INJECTION playbook tested
[ ] DEFENSE_EVASION playbook tested

Issues Found:
_________________________________
_________________________________

Notes:
_________________________________
_________________________________
```

---

## 🎉 Success Criteria

**Feature is working correctly if:**
1. ✅ Auto-refresh updates dashboard every N seconds
2. ✅ Settings persist across browser sessions
3. ✅ Errors are handled gracefully with backoff
4. ✅ All 4 new playbooks generate expected IOCs
5. ✅ Dashboard shows all MITRE techniques correctly
6. ✅ No console errors during normal operation
7. ✅ Performance is acceptable (no lag or freezing)

**Ready for production use!** 🚀
