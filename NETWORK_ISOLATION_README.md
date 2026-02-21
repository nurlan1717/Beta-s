# Network Isolation & Restore Feature (SOAR)

## Overview

This document describes the robust network isolation/restore feature for Windows hosts in RansomRun. The implementation uses a **firewall-based isolation** approach as the primary method, with adapter-disable as an alternative.

## Features

- **Three isolation modes**: `firewall`, `adapter`, `hybrid`
- **Pre-isolation state capture**: Stores adapter config, IPs, DNS, gateway
- **Local state file**: `C:\ProgramData\RansomRun\isolation_state.json` for recovery after reboot
- **Backend communication preserved**: Agent can still reach backend during isolation
- **Verification**: Post-isolation and post-restore connectivity tests
- **Idempotent**: Safe to call multiple times
- **Detailed logging**: Full command output, errors, and verification results

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/soar/isolate/{host_id}` | POST | Isolate a host |
| `/api/soar/restore-network/{host_id}` | POST | Restore network |
| `/api/soar/isolation-state/{host_id}` | GET | Get isolation status |
| `/api/soar/action-logs/{host_id}` | GET | Get action logs |
| `/api/soar/policies` | GET | List isolation modes |

## Isolation Modes

### 1. Firewall Mode (Recommended)
- Uses Windows Firewall to block all traffic
- Creates allow rules for backend IP/ports
- Agent can still communicate with backend
- Less obvious to user

### 2. Adapter Mode
- Disables network adapters via PowerShell
- Skips virtual adapters and loopback
- Works even if firewall is disabled/modified
- More obvious to user

### 3. Hybrid Mode
- Applies both firewall rules AND disables adapters
- Maximum isolation
- Most complex to restore

## Database Tables

### `host_isolation_states`
Stores pre-isolation network state for reliable restoration.

### `response_action_logs`
Detailed logs of all isolation/restore actions with stdout/stderr.

## Agent Tasks

- `soar_isolate_host`: Captures state, applies isolation, verifies
- `soar_restore_network`: Loads state, removes isolation, verifies

## Testing Steps

### 1. Start Backend
```powershell
cd C:\Users\Student\OneDrive...\RansomRun
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2. Start Agent (as Administrator)
```powershell
# MUST run as Administrator for isolation to work
cd C:\Users\Student\OneDrive...\RansomRun\agent
python agent.py
```

### 3. Test Isolation
1. Go to Hosts page → select a host
2. Choose isolation mode (default: firewall)
3. Click "Preview Isolation (Dry Run)" to see planned actions
4. Click "Isolate Host" to execute
5. Verify:
   - UI shows "ISOLATED" status
   - Agent log shows isolation success
   - `ping 8.8.8.8` fails on isolated host
   - Agent still communicates with backend

### 4. Test Restore
1. Click "Restore Network"
2. Verify:
   - UI shows "ONLINE" status
   - `ping 8.8.8.8` succeeds
   - DNS works (`nslookup google.com`)

### 5. Test Idempotency
- Call isolate twice → second call returns "already isolated"
- Call restore twice → second call returns "not isolated"

### 6. Test Reboot Recovery
1. Isolate host
2. Reboot the Windows VM
3. Start agent
4. Click "Restore Network"
5. Agent loads state from `C:\ProgramData\RansomRun\isolation_state.json`
6. Network restored successfully

## Troubleshooting Checklist

### Agent Not Running as Admin
**Symptom**: Isolation fails with "Administrator privileges required"
**Fix**: Run agent as Administrator:
```powershell
Start-Process powershell -Verb RunAs -ArgumentList "cd C:\path\to\agent; python agent.py"
```

### PowerShell Execution Policy
**Symptom**: PowerShell commands fail
**Fix**: 
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```

### Windows Defender Blocking
**Symptom**: Firewall commands fail silently
**Fix**: Add exclusion for RansomRun directory in Windows Defender

### Adapter Not Re-enabling
**Symptom**: Network stays down after restore
**Fix**: Manual restore:
```powershell
Get-NetAdapter | Enable-NetAdapter -Confirm:$false
netsh advfirewall reset
```

### State File Missing After Reboot
**Symptom**: Restore can't find pre-isolation state
**Fix**: Use force restore:
```json
POST /api/soar/restore-network/{host_id}
{"force": true}
```

### Backend IP Wrong
**Symptom**: Agent can't reach backend after isolation
**Fix**: Set environment variable:
```powershell
$env:RANSOMRUN_BACKEND_IP = "192.168.1.100"
```

### Firewall Rules Not Applying
**Symptom**: Isolation reports success but internet still works
**Fix**: Check Windows Firewall service:
```powershell
Get-Service MpsSvc | Start-Service
netsh advfirewall show allprofiles
```

### Multiple Adapters
**Symptom**: Only one adapter isolated
**Fix**: Use hybrid mode which handles all adapters:
```json
{"mode": "hybrid"}
```

## Files Modified

### Backend
- `app/models.py` - Added `HostIsolationState`, `ResponseActionLog`, `IsolationMode`
- `app/routers/soar.py` - New SOAR router with isolation endpoints
- `app/main.py` - Registered SOAR router

### Agent
- `agent/agent.py` - Added `soar_isolate_host`, `soar_restore_network` and helper methods

### UI
- `app/templates/host_detail.html` - Enhanced isolation controls with action logs

## Local State File Format

Location: `C:\ProgramData\RansomRun\isolation_state.json`

```json
{
  "isolated": true,
  "mode": "firewall",
  "timestamp": "2024-01-15T10:30:00",
  "pre_state": {
    "adapters": [
      {
        "name": "Ethernet",
        "interface_index": 5,
        "mac_address": "AA-BB-CC-DD-EE-FF",
        "status": "Up",
        "was_enabled": true,
        "ip_addresses": ["192.168.1.100"],
        "default_gateway": "192.168.1.1",
        "dns_servers": ["8.8.8.8"]
      }
    ],
    "firewall_profiles": {
      "Domain": true,
      "Private": true,
      "Public": true
    }
  },
  "backend_ip": "127.0.0.1",
  "backend_ports": [8000],
  "firewall_rules": ["RANSOMRUN_ALLOW_OUT_8000", "RANSOMRUN_ALLOW_IN"]
}
```

## Emergency Manual Restore

If all else fails:

```powershell
# 1. Reset firewall to defaults
netsh advfirewall reset

# 2. Set allow outbound policy
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

# 3. Enable all adapters
Get-NetAdapter | Enable-NetAdapter -Confirm:$false

# 4. If still blocked, disable firewall
netsh advfirewall set allprofiles state off

# 5. Clean up state file
Remove-Item "C:\ProgramData\RansomRun\isolation_state.json" -Force
```
