# ELK SIEM Dashboard - Auto-Refresh Feature

## Overview
The ELK SIEM Dashboard now includes a comprehensive **Auto-Refresh** feature that automatically updates dashboard data at configurable intervals, providing real-time monitoring capabilities similar to enterprise SIEM platforms.

---

## Features Implemented

### 1. **UI Controls**
Located in the dashboard header:
- **Auto Refresh Toggle**: Checkbox to enable/disable auto-refresh
- **Interval Dropdown**: Select refresh interval (5s, 10s, 30s, 60s)
- **Last Updated Label**: Shows timestamp of last successful refresh
- **Last Error Display**: Shows connection errors when they occur
- **Manual Refresh Button**: Trigger immediate refresh

### 2. **Auto-Refresh Behavior**
- **Partial Page Updates**: Uses AJAX (fetch API) to update data without full page reload
- **localStorage Persistence**: Settings are saved and restored across sessions
  - `elk_auto_refresh_enabled` - Toggle state
  - `elk_auto_refresh_interval_seconds` - Selected interval
- **Automatic Start**: If enabled, auto-refresh starts immediately on page load

### 3. **Data Refreshed**
The following dashboard components are updated:
- **Connection Status** (`/api/siem/elk/status`)
  - Connected/Disconnected badge
  - Elasticsearch version
  - Mock mode indicator
  
- **Summary Statistics** (`/api/siem/elk/stats?hours=24`)
  - Total Endpoints
  - Active Endpoints
  - Total Alerts (last 24h)
  - High Severity Alerts
  
- **Recent Alerts Table** (`/api/siem/elk/alerts?limit=20&hours=24`)
  - Last 20 alerts from past 24 hours
  - Timestamp, Endpoint, Rule ID, Description, MITRE technique, Severity
  
- **Endpoints List** (`/api/siem/elk/agents`)
  - All registered agents/endpoints
  - Status (active/inactive)
  
- **MITRE ATT&CK Heatmap** (`/api/siem/elk/mitre/heatmap`)
  - Technique frequency visualization

### 4. **Error Handling & Robustness**
- **In-Flight Guard**: Prevents overlapping refresh requests
- **Error Display**: Shows connection errors in red below "Last Updated"
- **Backoff Strategy**: 
  - Tracks consecutive errors
  - After 3 consecutive failures, doubles refresh interval
  - Maximum backoff: 60 seconds
  - Resets to normal interval on successful refresh
- **Graceful Degradation**: Individual component failures don't crash entire refresh

---

## Usage Instructions

### Basic Usage
1. **Navigate to ELK Dashboard**: `http://localhost:8000/elk-dashboard` (or your server URL)
2. **Enable Auto-Refresh**: Check the "Auto Refresh" toggle
3. **Select Interval**: Choose from dropdown (default: 10s)
4. **Monitor**: Dashboard updates automatically

### Settings Persistence
- Settings are saved to browser's localStorage
- Survives page refreshes and browser restarts
- Per-browser (not synced across devices)

### Manual Refresh
- Click "Refresh" button anytime for immediate update
- Works regardless of auto-refresh state
- Updates "Last Updated" timestamp

---

## API Endpoints Used

All endpoints are under `/api/siem/elk/`:

| Endpoint | Method | Purpose | Parameters |
|----------|--------|---------|------------|
| `/elk/status` | GET | Connection status | None |
| `/elk/stats` | GET | Dashboard statistics | `hours=24` |
| `/elk/alerts` | GET | Recent alerts | `limit=20&hours=24&host_name=<optional>` |
| `/elk/agents` | GET | Endpoint list | None |
| `/elk/mitre/heatmap` | GET | MITRE heatmap data | `hours=168` (default) |

---

## Enhanced Agent Playbooks

The agent has been updated with **4 new advanced playbooks** for comprehensive SIEM testing:

### 9. **CREDENTIAL_DUMP** - Credential Access Simulation
Simulates credential harvesting techniques:
- **T1003.001**: LSASS memory dump
- **T1003.002**: SAM database access
- **T1552**: Credential file harvesting

**Scenario Config:**
```json
{
  "simulate_credential_dump": true
}
```

**Generated IOCs:**
- File: `C:\RansomTest\ExfilStaging\lsass_dump.dmp`
- Files: Browser passwords, WiFi credentials, saved passwords
- Registry: SAM, SYSTEM, SECURITY access logs

---

### 10. **REGISTRY_PERSISTENCE** - Registry Manipulation
Simulates persistence mechanisms:
- **T1547.001**: Run key persistence
- **T1543.003**: Malicious service creation
- **T1053.005**: Scheduled task creation

**Scenario Config:**
```json
{
  "simulate_registry_persistence": true
}
```

**Generated IOCs:**
- Registry keys: HKCU/HKLM Run keys
- Service: `WindowsSecurityService`
- Scheduled Task: `SystemMaintenanceTask`

---

### 11. **PROCESS_INJECTION** - Code Injection Simulation
Simulates process injection techniques:
- **T1055.012**: Process hollowing
- **T1055.001**: DLL injection
- **T1620**: Reflective code loading

**Scenario Config:**
```json
{
  "simulate_process_injection": true
}
```

**Targets:**
- Processes: svchost.exe, explorer.exe, notepad.exe
- DLL: `C:\Windows\Temp\payload.dll`

---

### 12. **DEFENSE_EVASION** - Anti-Detection Techniques
Simulates evasion and anti-forensics:
- **T1070.001**: Event log clearing
- **T1070.006**: Timestomping
- **T1562.001**: Disable security tools

**Scenario Config:**
```json
{
  "simulate_defense_evasion": true
}
```

**Actions:**
- Clears: Security, System, Application, Sysmon logs
- Timestomps: Malware executables
- Disables: Windows Defender, Sysmon, Firewall

---

## Complete Playbook List

| # | Playbook | MITRE Techniques | Description |
|---|----------|------------------|-------------|
| 1 | CRYPTO_BASIC | T1486 | Basic file encryption |
| 2 | CRYPTO_ADVANCED | T1486, T1490, T1547, T1071 | Advanced ransomware |
| 3 | WIPER | T1485, T1490 | Destructive wiper |
| 4 | EXFILTRATION | T1560, T1041 | Data theft |
| 5 | LATERAL_MOVEMENT | T1046, T1021 | Network propagation |
| 6 | CLOUD_ATTACK | T1530, T1485 | Cloud storage attack |
| 7 | POLYMORPHIC | T1027 | Evasion techniques |
| 8 | APT_FULL_CHAIN | All above | Complete kill chain |
| 9 | CREDENTIAL_DUMP | T1003, T1552 | Credential harvesting |
| 10 | REGISTRY_PERSISTENCE | T1547, T1543, T1053 | Registry manipulation |
| 11 | PROCESS_INJECTION | T1055, T1620 | Code injection |
| 12 | DEFENSE_EVASION | T1070, T1562 | Anti-forensics |

---

## Testing & Verification

### Test Auto-Refresh Feature

1. **Start Backend Server:**
   ```powershell
   cd C:\Users\Student\OneDrive - Innovation and Digital Development Agency\Desktop\RansomRun
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Open Dashboard:**
   - Navigate to: `http://localhost:8000/elk-dashboard`
   - Or: `http://192.168.10.55:8000/elk-dashboard` (from network)

3. **Verify Auto-Refresh:**
   - Enable "Auto Refresh" toggle
   - Select "5s" interval for quick testing
   - Watch "Last Updated" timestamp change every 5 seconds
   - Open browser DevTools (F12) → Console to see refresh logs

4. **Test Error Handling:**
   - Stop Elasticsearch (if running)
   - Watch status change to "Disconnected"
   - Observe error message appear
   - Verify backoff strategy (interval increases after 3 failures)

5. **Test localStorage Persistence:**
   - Enable auto-refresh with 30s interval
   - Refresh browser (F5)
   - Verify toggle is still checked and interval is 30s
   - Verify auto-refresh continues

### Test New Playbooks

1. **Start Agent on Windows Machine:**
   ```powershell
   cd C:\RansomRun\agent
   python agent.py
   ```

2. **Create Test Scenario (via Web UI or API):**
   ```json
   {
     "scenario_key": "credential_dump_test",
     "scenario_config": {
       "simulate_credential_dump": true,
       "simulate_registry_persistence": true,
       "simulate_process_injection": true,
       "simulate_defense_evasion": true
     }
   }
   ```

3. **Verify in Dashboard:**
   - Watch alerts appear in real-time
   - Check MITRE heatmap for new techniques
   - Verify IOCs in alert details

---

## Browser Compatibility

Tested and working on:
- ✅ Chrome/Edge (Chromium)
- ✅ Firefox
- ✅ Safari (macOS)

**Requirements:**
- JavaScript enabled
- localStorage enabled
- Modern browser (ES6+ support)

---

## Troubleshooting

### Auto-Refresh Not Working
1. **Check Console**: Open DevTools (F12) → Console for errors
2. **Verify Toggle**: Ensure checkbox is checked
3. **Check Backend**: Verify FastAPI server is running
4. **Clear localStorage**: 
   ```javascript
   localStorage.removeItem('elk_auto_refresh_enabled');
   localStorage.removeItem('elk_auto_refresh_interval_seconds');
   ```

### High CPU Usage
- Increase refresh interval (use 30s or 60s)
- Disable auto-refresh when not actively monitoring

### Data Not Updating
1. Check network tab for failed requests
2. Verify API endpoints are responding
3. Check Elasticsearch connection status
4. Review backend logs for errors

### localStorage Not Persisting
- Check browser privacy settings
- Ensure cookies/storage not blocked
- Try different browser

---

## Performance Considerations

### Recommended Intervals
- **Active Monitoring**: 5-10 seconds
- **Background Monitoring**: 30-60 seconds
- **Low Activity**: Disable auto-refresh, use manual refresh

### Network Impact
- Each refresh makes 5 API calls
- At 10s interval: ~30 requests/minute
- At 60s interval: ~5 requests/minute

### Server Load
- Minimal impact with proper indexing
- Database queries are optimized
- Consider disabling for 10+ concurrent users

---

## Security Notes

- Auto-refresh uses same authentication as manual requests
- No sensitive data stored in localStorage
- All API calls respect user permissions
- HTTPS recommended for production

---

## Future Enhancements

Potential improvements:
- WebSocket support for true real-time updates
- Configurable refresh per-component
- Alert sound notifications
- Export auto-refresh logs
- Dashboard performance metrics

---

## Summary

The auto-refresh feature provides:
✅ Real-time SIEM monitoring
✅ Configurable refresh intervals
✅ Persistent user preferences
✅ Robust error handling
✅ Professional UX
✅ 12 comprehensive playbooks for testing

**Status**: Production-ready for lab/educational environments
