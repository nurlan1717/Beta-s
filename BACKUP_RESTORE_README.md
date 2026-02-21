# Backup & Restore Feature

**LAB-SAFE** backup and recovery system for RansomRun ransomware simulation platform.

## Overview

This feature allows you to:
1. **Define Backup Plans** - Specify what folders to protect
2. **Create Snapshots** - Backup data before/during simulations  
3. **Restore Data** - Recover files after ransomware simulation
4. **Track Metrics** - RTO/RPO for executive reporting

## Quick Start

### 1. Restart the Server

```powershell
cd "C:\Users\Student\OneDrive - Innovation and Digital Development Agency\Desktop\RansomRun"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 2. Access the UI

- **Backup Plans**: http://192.168.10.55:8000/backup/plans
- **Backup & Recovery**: http://192.168.10.55:8000/backup/recovery

### 3. Create a Backup Plan

1. Go to **Recovery → Backup Plans** in the sidebar
2. Click **Create Plan**
3. Enter:
   - Name: `Target Data Protection`
   - Paths: `C:\RansomTest\target_data`
   - Schedule: `Before Each Simulation` (or Manual)
   - Retention: `5` snapshots
4. Click **Create Plan**

### 4. Run a Backup

1. Go to **Recovery → Backup & Restore**
2. Select a **Host** and **Plan**
3. Click **Run Backup Now**
4. The agent will execute the backup task

### 5. Restore After Simulation

1. Run a ransomware simulation (files get "encrypted")
2. Go to **Recovery → Backup & Restore**
3. Select the host and plan
4. Click **Restore Latest**
5. Choose restore mode:
   - **In-Place**: Overwrite original files
   - **Restore to New Folder**: Safe review first
6. Optionally check **Dry Run** to simulate
7. Click **Restore Now**

---

## API Endpoints

### Backup Plans

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/backup/plans` | Create a new plan |
| GET | `/api/backup/plans` | List all plans |
| GET | `/api/backup/plans/{id}` | Get plan details |
| PUT | `/api/backup/plans/{id}` | Update a plan |
| DELETE | `/api/backup/plans/{id}` | Disable a plan |

### Execute Backup/Restore

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/backup/run/backup` | Start a backup job |
| POST | `/api/backup/run/restore` | Start a restore job |

### Jobs & Snapshots

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/backup/jobs` | List backup/restore jobs |
| GET | `/api/backup/jobs/{id}` | Get job details |
| GET | `/api/backup/snapshots` | List snapshots |
| GET | `/api/backup/metrics` | Get RTO/RPO metrics |

---

## Database Tables

Three new tables are created automatically:

### backup_plans
- `id`, `name`, `description`
- `paths_json` - List of paths to backup
- `schedule_type` - manual, pre_simulation, interval
- `retention_count` - Number of snapshots to keep
- `enabled` - Boolean

### backup_jobs
- `id`, `host_id`, `plan_id`, `run_id`
- `job_type` - backup or restore
- `status` - pending, running, success, failed
- `started_at`, `ended_at`, `duration_seconds`
- `details_json` - Full execution details

### backup_snapshots
- `id`, `host_id`, `plan_id`
- `snapshot_time`, `storage_path`
- `file_count`, `total_bytes`
- `manifest_path` - SHA256 hash manifest
- `integrity_status` - ok, warn, fail

---

## Agent Tasks

The Windows agent handles two task types:

### backup_create
- Validates paths are in allowed directories
- Uses `robocopy` for reliable copying
- Creates `manifest.json` with file counts/sizes
- Creates `sha256_manifest.txt` for integrity
- Enforces retention (deletes old snapshots)

### backup_restore
- Validates snapshot exists
- Supports in-place or alternate folder restore
- Verifies file integrity via hash sampling
- Reports detailed results

---

## Allowed Directories (LAB-SAFE)

Only these paths can be backed up/restored:
- `C:\RansomTest\...`
- `C:\target_data\...`
- `C:\ProgramData\RansomRun\...`
- `C:\RestoreTest\...` (restore only)

---

## Snapshot Storage

Default location:
```
C:\ProgramData\RansomRun\backups\
  └── {hostname}\
      └── {plan_name}\
          └── {timestamp}\
              ├── manifest.json
              ├── sha256_manifest.txt
              └── RansomTest\
                  └── target_data\
                      └── ... (backed up files)
```

---

## RTO/RPO Metrics

Available at `/api/backup/metrics`:

```json
{
  "mean_rto_seconds": 12.5,
  "mean_rto_display": "0m 12s",
  "recovery_success_rate": 100.0,
  "total_restore_jobs": 5,
  "rpo_seconds": 3600,
  "rpo_display": "1h 0m",
  "latest_snapshot_time": "2024-12-18T10:30:00"
}
```

---

## RBAC (Role-Based Access)

| Action | Allowed Roles |
|--------|---------------|
| View plans/jobs | All authenticated users |
| Create/modify plans | ADMIN, SENIOR_ANALYST |
| Execute restore | ADMIN, SENIOR_ANALYST |
| Execute backup | All authenticated users |

---

## Demo Walkthrough

1. **Create test data**:
   ```powershell
   mkdir C:\RansomTest\target_data
   echo "Important document" > C:\RansomTest\target_data\report.docx
   echo "Financial data" > C:\RansomTest\target_data\budget.xlsx
   ```

2. **Create backup plan** via UI or API:
   ```bash
   curl -X POST http://192.168.10.55:8000/api/backup/plans \
     -H "Content-Type: application/json" \
     -d '{"name":"Demo Plan","paths":["C:\\RansomTest\\target_data"],"schedule_type":"manual"}'
   ```

3. **Run backup**:
   ```bash
   curl -X POST http://192.168.10.55:8000/api/backup/run/backup \
     -H "Content-Type: application/json" \
     -d '{"host_id":1,"plan_id":1}'
   ```

4. **Simulate ransomware** (files get renamed to .locked)

5. **Restore from backup**:
   ```bash
   curl -X POST http://192.168.10.55:8000/api/backup/run/restore \
     -H "Content-Type: application/json" \
     -d '{"host_id":1,"plan_id":1,"snapshot_id":"latest","restore_mode":"in_place"}'
   ```

6. **Verify** files are restored to original state

---

## Troubleshooting

### Tables not created
Restart the server - tables are created on startup via `init_db()`.

### Agent not executing tasks
- Ensure agent is running as Administrator
- Check agent logs at `C:\RansomTest\agent.log`
- Verify agent is connected to backend

### Backup fails
- Check path is in allowed directories
- Verify source path exists
- Check for disk space

### Restore fails
- Verify snapshot path exists
- Check file permissions
- Try dry_run first to preview

---

## Files Added/Modified

### New Files
- `app/models_backup.py` - Database models
- `app/crud_backup.py` - CRUD operations
- `app/templates/backup_plans.html` - Plans UI
- `app/templates/backup_recovery.html` - Recovery UI

### Modified Files
- `app/routers/backup.py` - Extended API endpoints
- `app/routers/ui.py` - Added page routes
- `app/database.py` - Import backup models
- `app/templates/base.html` - Navigation links
- `agent/agent.py` - backup_create/backup_restore tasks
