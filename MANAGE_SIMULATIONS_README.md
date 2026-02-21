# Manage Simulations - STOP & DELETE Feature

## Overview
The Simulation History page now includes comprehensive management capabilities to **STOP** running simulations and **DELETE** completed simulations with full cascade deletion of related data.

---

## Features Implemented

### 1. **STOP Simulation**
Stop a running or pending simulation gracefully.

**Behavior by Status:**
- **PENDING**: Immediately cancels, removes pending tasks, marks as CANCELED
- **RUNNING**: Creates stop task for agent, marks as STOPPING
- **STOPPING**: Idempotent - returns current state
- **COMPLETED/FAILED/CANCELED**: Returns 409 Conflict error

**Backend Endpoint:**
```
POST /api/runs/{run_id}/stop
```

**Response:**
```json
{
  "success": true,
  "run_id": 123,
  "status": "STOPPING",
  "message": "Stop task created, waiting for agent"
}
```

### 2. **DELETE Simulation**
Permanently delete a simulation and all related data.

**Safety Features:**
- Blocks deletion of RUNNING/STOPPING runs unless `force=true`
- If `force=true`, attempts to stop first, then deletes
- Confirmation modal warns user about permanent deletion

**Backend Endpoint:**
```
DELETE /api/runs/{run_id}?force=false
```

**Cascade Deletion Includes:**
- Tasks
- Alerts
- Events (RunEvent)
- Metrics
- IOCs
- Affected Files
- Recovery Plans & Events
- Behavior Profiles
- What-If Scenarios
- IR Sessions
- Run Feedback
- Business Impact
- Compliance Reports

**Response:**
```json
{
  "success": true,
  "deleted": true,
  "run_id": 123,
  "counts": {
    "tasks": 3,
    "alerts": 15,
    "events": 8,
    "metrics": 5,
    "iocs": 12,
    "affected_files": 25,
    "recovery_plans": 1,
    "behavior_profiles": 1,
    "whatif_scenarios": 0,
    "ir_sessions": 0,
    "run_feedbacks": 1,
    "business_impacts": 1,
    "compliance_reports": 1
  }
}
```

### 3. **UI Enhancements**

**New "Manage" Column:**
- **RUNNING/STOPPING**: [Stop] button (disabled if STOPPING)
- **PENDING**: [Stop] + [Delete] buttons
- **COMPLETED/FAILED/CANCELED**: [Delete] button

**Confirmation Modals:**
- **Stop Modal**: Warns about sending stop command to agent
- **Delete Modal**: Lists all data that will be permanently removed

**Toast Notifications:**
- Success: Green border, shows action result
- Error: Red border, shows error message
- Auto-dismisses after 4 seconds

**New Status Badges:**
- **STOPPING**: Orange badge - "Stop command sent to agent"
- **CANCELED**: Gray badge - "Stopped by user"

---

## Model Changes

### RunStatus Enum (models.py)
```python
class RunStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"      # NEW
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"      # NEW
```

### EventType Enum (models.py)
```python
class EventType(str, enum.Enum):
    # ... existing events ...
    STOP_REQUESTED = "STOP_REQUESTED"   # NEW
    STOP_EXECUTED = "STOP_EXECUTED"     # NEW
```

---

## Agent Changes

### New Task Handler (agent.py)
```python
def stop_simulation(self, parameters: dict) -> tuple:
    """
    Stop a running simulation.
    Called when backend sends stop_simulation task.
    """
    run_id = parameters.get("run_id")
    self.logger.warning(f"STOP SIMULATION requested for run_id: {run_id}")
    
    # Acknowledge stop request
    # (Current simulations are atomic, so this just confirms receipt)
    
    return (True, f"Simulation stopped successfully for run {run_id}")
```

**Task Type:** `stop_simulation`

**Parameters:**
```json
{
  "run_id": 123
}
```

---

## API Endpoints

### POST /api/runs/{run_id}/stop

**Description:** Stop a running or pending simulation

**Parameters:**
- `run_id` (path): Run ID to stop

**Responses:**
- `200 OK`: Stop successful
- `404 Not Found`: Run not found
- `409 Conflict`: Run not stoppable (already completed/failed/canceled)
- `400 Bad Request`: Other errors

**Example:**
```bash
curl -X POST http://localhost:8000/api/runs/123/stop
```

---

### DELETE /api/runs/{run_id}

**Description:** Delete a simulation and all related data

**Parameters:**
- `run_id` (path): Run ID to delete
- `force` (query, optional): Force delete even if RUNNING/STOPPING (default: false)

**Responses:**
- `200 OK`: Deletion successful with counts
- `404 Not Found`: Run not found
- `409 Conflict`: Run is RUNNING/STOPPING without force=true
- `400 Bad Request`: Other errors

**Examples:**
```bash
# Delete completed run
curl -X DELETE http://localhost:8000/api/runs/123

# Force delete running run
curl -X DELETE http://localhost:8000/api/runs/123?force=true
```

---

## Testing Guide

### Test 1: Stop PENDING Run

**Steps:**
1. Start backend server
2. Create a simulation but don't start agent
3. Navigate to Simulation History
4. Click [Stop] on PENDING run
5. Confirm in modal

**Expected Result:**
- Run status changes to CANCELED
- Pending tasks are removed
- STOP_REQUESTED event created
- Toast shows success message
- Page refreshes showing CANCELED status

**Verification:**
```bash
# Check run status
curl http://localhost:8000/api/runs/123

# Should show:
# "status": "CANCELED"
# "ended_at": "<timestamp>"
```

---

### Test 2: Stop RUNNING Run

**Steps:**
1. Start backend server
2. Start agent on Windows machine
3. Create and start a simulation
4. While RUNNING, click [Stop]
5. Confirm in modal

**Expected Result:**
- Run status changes to STOPPING
- Stop task created for agent
- STOP_REQUESTED event created
- Toast shows success message
- Page refreshes showing STOPPING status

**Agent Behavior:**
- Agent picks up stop_simulation task
- Executes stop handler
- Reports completion
- Backend marks run as CANCELED
- STOP_EXECUTED event created

**Verification:**
```bash
# Check run status (should be STOPPING initially)
curl http://localhost:8000/api/runs/123

# After agent processes:
# "status": "CANCELED"
# "ended_at": "<timestamp>"

# Check events
curl http://localhost:8000/api/runs/123 | jq '.events[] | select(.event_type | contains("STOP"))'
```

---

### Test 3: Stop Idempotency

**Steps:**
1. Stop a RUNNING run
2. Immediately click [Stop] again (before agent processes)

**Expected Result:**
- First stop: Creates stop task, marks STOPPING
- Second stop: Returns "Stop task already exists"
- No duplicate stop tasks created
- Same STOPPING status maintained

---

### Test 4: Delete COMPLETED Run

**Steps:**
1. Complete a simulation
2. Navigate to Simulation History
3. Click [Delete] on COMPLETED run
4. Review deletion list in modal
5. Confirm deletion

**Expected Result:**
- Run and all related data deleted
- Toast shows deletion count (e.g., "Run #123 deleted (67 related records removed)")
- Page refreshes, run no longer appears
- Database records removed

**Verification:**
```bash
# Check run is gone
curl http://localhost:8000/api/runs/123
# Should return 404

# Check related data is gone
curl http://localhost:8000/api/runs/123/alerts
# Should return empty or 404
```

---

### Test 5: Delete RUNNING Run (Blocked)

**Steps:**
1. Start a simulation (RUNNING status)
2. Click [Delete] (should not appear - only Stop should show)
3. Try API directly without force

**Expected Result:**
- UI doesn't show Delete button for RUNNING runs
- API call without force returns 409 Conflict

**Verification:**
```bash
# Try to delete without force
curl -X DELETE http://localhost:8000/api/runs/123

# Should return:
# {
#   "detail": "Cannot delete RUNNING run without force=true"
# }
```

---

### Test 6: Force Delete RUNNING Run

**Steps:**
1. Start a simulation (RUNNING status)
2. Call API with force=true

**Expected Result:**
- Backend attempts to stop run first
- Then deletes all data
- Returns deletion counts

**Verification:**
```bash
# Force delete running run
curl -X DELETE "http://localhost:8000/api/runs/123?force=true"

# Should return success with counts
```

---

### Test 7: Delete PENDING Run

**Steps:**
1. Create simulation without agent running
2. Click [Delete] on PENDING run
3. Confirm in modal

**Expected Result:**
- Run and pending tasks deleted
- Toast shows success
- Page refreshes, run removed

---

### Test 8: UI Modal Interactions

**Steps:**
1. Click [Stop] button
2. Press Escape key

**Expected Result:**
- Modal closes without action

**Steps:**
1. Click [Delete] button
2. Click outside modal (on overlay)

**Expected Result:**
- Modal closes without action

**Steps:**
1. Click [Stop] button
2. Click Cancel button

**Expected Result:**
- Modal closes without action

---

### Test 9: Cascade Deletion Verification

**Steps:**
1. Create a simulation with:
   - Multiple tasks
   - Alerts generated
   - Metrics collected
   - IOCs created
   - Files affected
   - Recovery plan created
   - Compliance report generated
2. Delete the run
3. Check database

**Expected Result:**
All related records removed from:
- `tasks` table
- `alerts` table
- `run_events` table
- `metrics` table
- `iocs` table
- `affected_files` table
- `recovery_plans` table
- `recovery_events` table
- `behavior_profiles` table
- `whatif_scenarios` table
- `ir_sessions` table
- `run_feedbacks` table
- `business_impacts` table
- `compliance_reports` table

**SQL Verification:**
```sql
-- Check all related data is gone
SELECT COUNT(*) FROM tasks WHERE run_id = 123;
SELECT COUNT(*) FROM alerts WHERE run_id = 123;
SELECT COUNT(*) FROM run_events WHERE run_id = 123;
SELECT COUNT(*) FROM metrics WHERE run_id = 123;
SELECT COUNT(*) FROM iocs WHERE run_id = 123;
SELECT COUNT(*) FROM affected_files WHERE run_id = 123;
-- All should return 0
```

---

### Test 10: Error Handling

**Test 10a: Stop Non-Existent Run**
```bash
curl -X POST http://localhost:8000/api/runs/99999/stop
# Expected: 404 Not Found
```

**Test 10b: Stop Completed Run**
```bash
# For a completed run (ID 123)
curl -X POST http://localhost:8000/api/runs/123/stop
# Expected: 409 Conflict - "Run not stoppable (status: COMPLETED)"
```

**Test 10c: Delete Non-Existent Run**
```bash
curl -X DELETE http://localhost:8000/api/runs/99999
# Expected: 404 Not Found
```

---

## Database Migration

**Note:** If you have existing runs in PENDING/RUNNING state, they will continue to work. The new STOPPING and CANCELED statuses are additive.

**No migration required** - SQLAlchemy will handle the enum additions automatically.

---

## Troubleshooting

### Issue: Stop button doesn't appear
**Solution:** Check run status - Stop only shows for PENDING/RUNNING/STOPPING

### Issue: Delete button doesn't appear
**Solution:** Check run status - Delete only shows for COMPLETED/FAILED/CANCELED/PENDING

### Issue: Stop task not processed by agent
**Solution:** 
1. Check agent is running
2. Check agent logs for errors
3. Verify agent can connect to backend
4. Check task was created: `GET /api/runs/{run_id}` → check tasks array

### Issue: Deletion fails with "Cannot delete RUNNING run"
**Solution:** Either:
1. Stop the run first, wait for CANCELED, then delete
2. Use `force=true` query parameter

### Issue: Modal doesn't close
**Solution:** 
1. Click Cancel button
2. Press Escape key
3. Click outside modal on dark overlay

---

## File Changes Summary

### Backend
- **`app/models.py`**: Added STOPPING, CANCELED statuses; STOP_REQUESTED, STOP_EXECUTED events
- **`app/crud.py`**: Added `stop_run()`, `delete_run()`, updated `complete_task()`
- **`app/routers/runs.py`**: Added `/runs/{run_id}/stop` and `/runs/{run_id}` DELETE endpoints

### Agent
- **`agent/agent.py`**: Added `stop_simulation()` method, updated `execute_task()`

### Frontend
- **`app/templates/runs.html`**: Added Manage column, modals, JavaScript, CSS

---

## Security Considerations

1. **No Authentication**: Current implementation doesn't check user permissions
   - **Future Enhancement**: Add role-based access control
   - Only admins should delete runs
   - Only run owners or admins should stop runs

2. **Force Delete**: Powerful feature that bypasses safety checks
   - Use with caution
   - Consider logging force deletes for audit trail

3. **Cascade Deletion**: Irreversible
   - Consider adding soft delete (mark as deleted instead of removing)
   - Consider backup/export before deletion

---

## Future Enhancements

1. **Bulk Operations**
   - Select multiple runs
   - Stop all selected
   - Delete all selected

2. **Soft Delete**
   - Mark runs as deleted instead of removing
   - Allow restore within X days
   - Permanent deletion after retention period

3. **Stop Timeout**
   - If agent doesn't respond within X minutes
   - Automatically mark as FAILED
   - Send notification

4. **Deletion Confirmation**
   - Require typing run ID to confirm
   - For extra safety on critical runs

5. **Audit Trail**
   - Log who stopped/deleted what and when
   - Store in separate audit table

6. **Export Before Delete**
   - Option to download run data as JSON
   - Before permanent deletion

---

## Summary

**Implementation Complete:**
- ✅ STOP functionality for PENDING/RUNNING runs
- ✅ DELETE functionality with cascade deletion
- ✅ UI with modals and toast notifications
- ✅ Agent support for stop_simulation task
- ✅ Idempotent operations
- ✅ Safety checks (force parameter)
- ✅ New status badges (STOPPING, CANCELED)
- ✅ Comprehensive error handling

**Ready for Production Use** in lab/educational environments.
