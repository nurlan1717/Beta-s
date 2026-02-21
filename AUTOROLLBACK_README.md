# AutoRollback Feature Documentation

## Overview

AutoRollback is an automated, safe "rollback to last known-good state" workflow for the RansomRun platform. It can be triggered after containment or when a ransomware detection is confirmed.

**Key Features:**
- Safe file-level rollback from backup snapshots
- Only operates on configured safe paths (lab directories)
- Full dry-run support
- Approval workflow for destructive operations
- Complete audit trail with before/after hashes
- Playbook integration for automated response

---

## Safety Constraints

### Safe Paths (Default Allowed)
- `C:\RansomTest`
- `C:\RansomLab`
- `C:\Users\Public\Documents`

### Blocked Paths (NEVER Modified)
- `C:\Windows`
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\ProgramData`
- `C:\$Recycle.Bin`
- `C:\System Volume Information`
- AppData directories
- User profile system files

---

## API Endpoints

### Create Rollback Plan
```
POST /api/rollback/plan
Body: {
    "host_id": 1,
    "run_id": null,              // Optional linked simulation run
    "snapshot_id": null,         // Optional, uses latest if not specified
    "safe_paths": null,          // Optional custom paths
    "conflict_policy": "QUARANTINE",  // QUARANTINE | OVERWRITE | SKIP
    "cleanup_extensions": null,  // Optional, e.g., [".locked", ".encrypted"]
    "dry_run": false,
    "require_approval": true
}
```

### Approve Plan
```
POST /api/rollback/plan/{plan_id}/approve
```

### Execute Plan
```
POST /api/rollback/execute/{plan_id}?dry_run=false&force=false
```

### List Plans
```
GET /api/rollback/plans?host_id=1&status=PENDING_APPROVAL&limit=50
```

### Get Plan Details
```
GET /api/rollback/plans/{plan_id}
```

### Get Execution Report
```
GET /api/rollback/reports/{plan_id}
```

### Cancel Plan
```
POST /api/rollback/plans/{plan_id}/cancel
```

---

## Database Models

### RollbackPlan
- `id`: Primary key
- `host_id`: Target host
- `run_id`: Optional linked simulation run
- `snapshot_id`: Backup snapshot to restore from
- `status`: DRAFT | PENDING_APPROVAL | APPROVED | EXECUTING | COMPLETED | PARTIAL | FAILED | CANCELED
- `dry_run`: Boolean
- `safe_paths`: JSON array of allowed paths
- `conflict_policy`: How to handle file conflicts
- `requires_approval`: Boolean
- `approved_by`: Username who approved
- `approved_at`: Approval timestamp

### RollbackFileAction
- `id`: Primary key
- `plan_id`: Parent plan
- `original_path`: File path to restore
- `backup_path`: Source backup path
- `action_type`: RESTORE | SKIP | CONFLICT_MOVE | CLEANUP_EXTENSION | FAIL
- `before_hash`: SHA256 hash before restore
- `expected_hash`: Expected hash from backup
- `after_hash`: Actual hash after restore
- `hash_verified`: Boolean
- `executed`: Boolean
- `success`: Boolean
- `error_message`: Error details if failed

### RollbackReport
- `id`: Primary key
- `plan_id`: Associated plan
- `files_restored`: Count
- `files_skipped`: Count
- `files_conflict_moved`: Count
- `files_cleaned_extensions`: Count
- `files_failed`: Count
- `hash_verifications_passed`: Count
- `hash_verifications_failed`: Count
- `elapsed_seconds`: Duration
- `final_status`: SUCCESS | PARTIAL | FAILED

---

## Agent Task Handlers

### rollback_restore_from_snapshot
Restores files from backup snapshot to original locations.

**Parameters:**
- `plan_id`: Rollback plan ID
- `dry_run`: Simulate without changes
- `safe_paths`: List of allowed paths
- `conflict_policy`: QUARANTINE | OVERWRITE | SKIP
- `restore_actions`: List of file actions
- `conflict_directory`: Where to move conflicting files

### rollback_verify_hashes
Verifies restored files match expected hashes.

**Parameters:**
- `plan_id`: Rollback plan ID
- `files`: List of {path, expected_hash}

### rollback_cleanup_extensions
Removes ransomware extensions (.locked, .encrypted, etc.).

**Parameters:**
- `safe_paths`: Paths to scan
- `extensions`: Extensions to remove
- `dry_run`: Simulate without changes

---

## Playbook Integration

Add `autorollback` action to playbooks:

```json
{
    "action_type": "autorollback",
    "parameters": {
        "mode": "EXECUTE_AFTER_APPROVAL",
        "conflict_policy": "QUARANTINE",
        "safe_paths": ["C:\\RansomTest"],
        "cleanup_extensions": [".locked", ".encrypted"]
    }
}
```

**Modes:**
- `PLAN_ONLY`: Create plan but don't execute
- `EXECUTE_AFTER_APPROVAL`: Create plan, wait for manual approval
- `AUTO_EXECUTE`: Create, approve, and execute automatically

---

## UI Pages

### /rollback
Main AutoRollback management page:
- Status overview
- Safe paths configuration
- Recent plans list
- Create new plan modal
- Plan detail view with approve/execute actions

---

## Demo/Test Steps

### 1. Setup Test Environment
```powershell
# Create test directory
mkdir C:\RansomTest
cd C:\RansomTest

# Create test files
echo "Confidential financial data" > financial_report.txt
echo "Employee records" > employees.csv
echo "Secret project info" > project_alpha.txt
```

### 2. Create Backup Snapshot
```bash
# Via API
curl -X POST http://localhost:8000/api/backup/snapshot/1 \
    -H "Content-Type: application/json"

# Or via UI: Hosts > Select Host > Create Backup
```

### 3. Simulate Ransomware Attack
```powershell
# Rename files to simulate encryption
cd C:\RansomTest
ren financial_report.txt financial_report.txt.locked
ren employees.csv employees.csv.locked
ren project_alpha.txt project_alpha.txt.locked
```

### 4. Trigger Alert (Optional)
Run a ransomware simulation or manually create alert RR-2001.

### 5. Create Rollback Plan (Dry Run)
```bash
curl -X POST http://localhost:8000/api/rollback/plan \
    -H "Content-Type: application/json" \
    -d '{
        "host_id": 1,
        "dry_run": true,
        "require_approval": false
    }'
```

### 6. Review Plan in UI
Navigate to `/rollback` and view the plan details.

### 7. Create and Execute Real Rollback
```bash
# Create plan
curl -X POST http://localhost:8000/api/rollback/plan \
    -H "Content-Type: application/json" \
    -d '{
        "host_id": 1,
        "dry_run": false,
        "require_approval": true
    }'

# Approve plan (replace {plan_id})
curl -X POST http://localhost:8000/api/rollback/plan/{plan_id}/approve

# Execute plan
curl -X POST http://localhost:8000/api/rollback/execute/{plan_id}
```

### 8. Verify Results
```powershell
# Check files restored
dir C:\RansomTest

# Check rollback report
curl http://localhost:8000/api/rollback/reports/{plan_id}
```

---

## Configuration

### Global Settings (SystemConfig table)
- `autorollback_enabled`: true/false (default: false)

### Per-Host Settings
- `allow_auto_response`: Must be true for auto-execute mode

### Playbook Settings
- `autorollback_mode`: OFF | PLAN_ONLY | EXECUTE_AFTER_APPROVAL | AUTO_EXECUTE

---

## Troubleshooting

### "Path not safe" errors
- Ensure file paths are under configured safe_paths
- Check that paths don't include blocked system directories

### "No backup snapshot found"
- Create a backup snapshot first via `/api/backup/snapshot/{host_id}`
- Ensure snapshot status is COMPLETED

### "Active rollback plan already exists"
- Another plan is pending/executing for this host
- Cancel or wait for the existing plan to complete

### Permission denied errors
- Agent may not have write access to target directory
- Run agent with appropriate permissions

---

## Files Changed

### New Files
- `app/services/rollback_engine.py` - AutoRollback engine
- `app/routers/rollback.py` - API endpoints
- `app/templates/rollback.html` - UI template

### Modified Files
- `app/models.py` - Added RollbackPlan, RollbackFileAction, RollbackReport models
- `app/main.py` - Registered rollback router
- `app/routers/ui.py` - Added /rollback route
- `app/templates/base.html` - Added sidebar link
- `app/services/playbook_engine.py` - Added autorollback action handler
- `agent/agent.py` - Added rollback task handlers

---

## Security Considerations

1. **Path Validation**: All paths are validated against safe_paths before any operation
2. **System Protection**: System directories are ALWAYS blocked, regardless of configuration
3. **Audit Trail**: Every file action is logged with before/after hashes
4. **Approval Workflow**: Destructive operations require approval by default
5. **Idempotency**: Plans cannot be executed twice without force flag
6. **Locking**: Parallel execution on same host is prevented

---

## Future Enhancements

- [ ] VSS snapshot integration (optional)
- [ ] Scheduled rollback points
- [ ] Differential rollback (only changed files)
- [ ] Cloud backup integration
- [ ] Email notifications for rollback events
- [ ] Rollback from specific timestamp
