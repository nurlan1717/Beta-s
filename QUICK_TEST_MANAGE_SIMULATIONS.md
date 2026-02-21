# Quick Test Guide - Manage Simulations (STOP & DELETE)

## 🚀 Quick Start (5 Minutes)

### Prerequisites
```powershell
# 1. Start Backend Server
cd "C:\Users\Student\OneDrive - Innovation and Digital Development Agency\Desktop\RansomRun"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 2. Start Agent (on Windows machine)
cd C:\RansomRun\agent
python agent.py
```

---

## ✅ Test Scenarios

### Test 1: Stop PENDING Run (30 seconds)

**Setup:**
1. Open browser: `http://localhost:8000/simulate`
2. Select a host and scenario
3. Click "Start Simulation"
4. **DO NOT** start the agent (keep it stopped)

**Test:**
1. Navigate to: `http://localhost:8000/runs`
2. Find the PENDING run (should be at top)
3. Click **[Stop]** button in Manage column
4. Review modal: "Stop run #X?"
5. Click **"Stop Simulation"**

**Expected Result:**
- ✅ Toast notification: "Run #X stopped successfully"
- ✅ Page refreshes automatically
- ✅ Run status changes to **CANCELED** (gray badge)
- ✅ Manage column now shows **[Delete]** button

**Verify in Database:**
```bash
curl http://localhost:8000/api/runs/X
# Check: "status": "CANCELED", "ended_at": "<timestamp>"
```

---

### Test 2: Stop RUNNING Run (1 minute)

**Setup:**
1. Start agent: `python agent.py`
2. Create and start a simulation
3. Wait for status to change to RUNNING

**Test:**
1. Navigate to: `http://localhost:8000/runs`
2. Find the RUNNING run
3. Click **[Stop]** button
4. Confirm in modal

**Expected Result:**
- ✅ Toast: "Run #X stopped successfully"
- ✅ Status changes to **STOPPING** (orange badge)
- ✅ Stop button becomes disabled
- ✅ Agent picks up stop task
- ✅ After ~5-10 seconds, status changes to **CANCELED**
- ✅ [Delete] button appears

**Verify Agent Logs:**
```
[INFO] Executing task X: stop_simulation
[WARNING] STOP SIMULATION requested for run_id: X
[INFO] Simulation stop acknowledged for run X
```

---

### Test 3: Delete COMPLETED Run (30 seconds)

**Setup:**
1. Complete a simulation (let it run to completion)
2. Wait for status = COMPLETED

**Test:**
1. Navigate to: `http://localhost:8000/runs`
2. Find COMPLETED run
3. Click **[Delete]** button
4. Review deletion warning modal
5. Click **"Delete Permanently"**

**Expected Result:**
- ✅ Toast: "Run #X deleted (67 related records removed)"
- ✅ Page refreshes
- ✅ Run no longer appears in list
- ✅ All related data removed from database

**Verify Deletion:**
```bash
curl http://localhost:8000/api/runs/X
# Should return 404 Not Found
```

---

### Test 4: Delete PENDING Run (30 seconds)

**Setup:**
1. Create simulation without agent running

**Test:**
1. Click **[Delete]** on PENDING run
2. Confirm deletion

**Expected Result:**
- ✅ Run and pending tasks deleted
- ✅ Toast shows success
- ✅ Run removed from list

---

### Test 5: Idempotency - Double Stop (30 seconds)

**Setup:**
1. Start a RUNNING simulation

**Test:**
1. Click **[Stop]** → Confirm
2. Wait for STOPPING status
3. Refresh page
4. Click **[Stop]** again (button should be disabled)

**Expected Result:**
- ✅ First stop: Creates stop task, marks STOPPING
- ✅ Second stop: Button is disabled (can't click)
- ✅ No duplicate tasks created

---

### Test 6: Modal Interactions (1 minute)

**Test 6a: Escape Key**
1. Click [Stop]
2. Press **Escape** key
3. ✅ Modal closes, no action taken

**Test 6b: Click Outside**
1. Click [Delete]
2. Click on dark overlay (outside modal)
3. ✅ Modal closes, no action taken

**Test 6c: Cancel Button**
1. Click [Stop]
2. Click **Cancel** button
3. ✅ Modal closes, no action taken

---

### Test 7: Force Delete via API (1 minute)

**Setup:**
1. Start a RUNNING simulation

**Test:**
```bash
# Try delete without force (should fail)
curl -X DELETE http://localhost:8000/api/runs/X
# Expected: {"detail": "Cannot delete RUNNING run without force=true"}

# Force delete
curl -X DELETE "http://localhost:8000/api/runs/X?force=true"
# Expected: {"success": true, "deleted": true, "counts": {...}}
```

**Expected Result:**
- ✅ First call: 409 Conflict error
- ✅ Second call: Success with deletion counts
- ✅ Run removed from database

---

### Test 8: UI Status Badges (2 minutes)

**Create runs in different states and verify badges:**

| Status | Badge Color | Text |
|--------|-------------|------|
| PENDING | Blue | PENDING |
| RUNNING | Green | RUNNING |
| STOPPING | Orange | STOPPING |
| COMPLETED | Green | COMPLETED |
| FAILED | Red | FAILED |
| CANCELED | Gray | CANCELED |

**Verify in Status Reference section:**
- ✅ All 6 statuses listed
- ✅ Descriptions accurate

---

### Test 9: Cascade Deletion (2 minutes)

**Setup:**
1. Create a simulation that generates:
   - Multiple tasks
   - Alerts
   - Metrics
   - IOCs
   - Affected files

**Test:**
1. Complete the simulation
2. Navigate to run detail page
3. Note counts: tasks, alerts, events, etc.
4. Go back to runs list
5. Delete the run
6. Check deletion count in toast

**Expected Result:**
- ✅ Toast shows total count matching sum of all related records
- ✅ All related data removed

**Verify:**
```bash
# Check run detail (should 404)
curl http://localhost:8000/api/runs/X

# Check alerts (should be empty)
curl http://localhost:8000/api/siem/alerts
# Should not contain alerts for run X
```

---

### Test 10: Error Handling (1 minute)

**Test 10a: Stop Non-Existent Run**
```bash
curl -X POST http://localhost:8000/api/runs/99999/stop
```
✅ Expected: 404 Not Found

**Test 10b: Stop Completed Run**
```bash
curl -X POST http://localhost:8000/api/runs/X/stop
# (where X is a completed run)
```
✅ Expected: 409 Conflict - "Run not stoppable"

**Test 10c: Delete Non-Existent Run**
```bash
curl -X DELETE http://localhost:8000/api/runs/99999
```
✅ Expected: 404 Not Found

---

## 🎯 Success Criteria

**All tests pass if:**
1. ✅ PENDING runs can be stopped instantly
2. ✅ RUNNING runs transition to STOPPING → CANCELED
3. ✅ COMPLETED/FAILED/CANCELED runs can be deleted
4. ✅ Cascade deletion removes all related data
5. ✅ Modals work correctly (Escape, click outside, Cancel)
6. ✅ Toast notifications appear and auto-dismiss
7. ✅ Page refreshes after actions
8. ✅ Status badges display correctly
9. ✅ Stop is idempotent (no duplicate tasks)
10. ✅ Force delete works for RUNNING runs
11. ✅ Error handling returns appropriate HTTP codes

---

## 🐛 Common Issues

### Issue: Stop button doesn't appear
**Fix:** Only shows for PENDING/RUNNING/STOPPING runs

### Issue: Delete button doesn't appear  
**Fix:** Only shows for COMPLETED/FAILED/CANCELED/PENDING runs

### Issue: Agent doesn't process stop task
**Fix:** 
1. Check agent is running
2. Check agent logs
3. Verify backend connectivity

### Issue: Modal won't close
**Fix:** Press Escape or click Cancel

### Issue: Toast doesn't appear
**Fix:** Check browser console for JavaScript errors

---

## 📊 Test Report Template

```
=== Manage Simulations Test Report ===
Date: _______________
Tester: _______________

[ ] Test 1: Stop PENDING run
[ ] Test 2: Stop RUNNING run  
[ ] Test 3: Delete COMPLETED run
[ ] Test 4: Delete PENDING run
[ ] Test 5: Idempotency test
[ ] Test 6: Modal interactions
[ ] Test 7: Force delete API
[ ] Test 8: Status badges
[ ] Test 9: Cascade deletion
[ ] Test 10: Error handling

Issues Found:
_________________________________
_________________________________

Notes:
_________________________________
_________________________________
```

---

## 🎉 Ready for Production!

If all tests pass, the Manage Simulations feature is ready for use in your lab/educational environment.

**Key Features Working:**
- ✅ Stop simulations (PENDING/RUNNING)
- ✅ Delete simulations with cascade
- ✅ Safety checks and confirmations
- ✅ Toast notifications
- ✅ Idempotent operations
- ✅ Agent integration
- ✅ Error handling
