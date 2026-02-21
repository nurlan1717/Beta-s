"""Backup and recovery API endpoints.

LAB-SAFE backup and restore for RansomRun platform.
Supports:
- Backup Plans (define what to protect)
- Backup Jobs (execute backups/restores)
- Snapshots (point-in-time backups)
- RTO/RPO metrics for reporting
"""

import os
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional, List

from ..database import get_db
from ..models import Host, Task, TaskStatus, Run, UserRole
from ..deps.auth import require_user

# Import new backup models and CRUD
try:
    from ..models_backup import (
        BackupPlan, BackupJob,
        BackupScopeType, BackupScheduleType, BackupJobType,
        BackupJobStatus, BackupIntegrityStatus, RestoreMode
    )
    from ..models import BackupSnapshot as LegacyBackupSnapshot
    from ..crud_backup import (
        create_backup_plan, get_backup_plan, get_all_backup_plans,
        get_pre_simulation_plans, update_backup_plan, delete_backup_plan,
        create_backup_job, get_backup_job, get_backup_jobs,
        start_backup_job, complete_backup_job,
        create_backup_task, get_rto_rpo_metrics,
        get_backup_snapshots, get_latest_snapshot, get_backup_snapshot
    )
    # Alias for compatibility
    get_latest_new_snapshot = get_latest_snapshot
    NEW_BACKUP_MODELS_AVAILABLE = True
except ImportError as e:
    print(f"Backup models import error: {e}")
    NEW_BACKUP_MODELS_AVAILABLE = False

# Legacy imports for backwards compatibility
try:
    from ..models import BackupSnapshot, RestoreEvent
    from ..services.backup_engine import BackupEngine
    LEGACY_BACKUP_AVAILABLE = True
except ImportError:
    LEGACY_BACKUP_AVAILABLE = False

router = APIRouter(prefix="/api/backup", tags=["backup"])


# =============================================================================
# PYDANTIC MODELS FOR NEW API
# =============================================================================

class BackupPlanCreate(BaseModel):
    """Request body for creating a backup plan."""
    name: str = Field(..., description="Unique plan name")
    description: Optional[str] = Field(None, description="Plan description")
    paths: List[str] = Field(..., description="Paths to backup")
    scope_type: str = Field(default="folder", description="folder or profile")
    schedule_type: str = Field(default="manual", description="manual, pre_simulation, or interval")
    interval_minutes: Optional[int] = Field(None, description="Interval in minutes for scheduled backups")
    retention_count: int = Field(default=5, description="Number of snapshots to retain")
    include_globs: Optional[List[str]] = Field(None, description="File patterns to include")
    exclude_globs: Optional[List[str]] = Field(None, description="File patterns to exclude")
    storage_base_path: Optional[str] = Field(None, description="Custom storage path")
    network_share_path: Optional[str] = Field(None, description="Network share for backups")


class BackupPlanUpdate(BaseModel):
    """Request body for updating a backup plan."""
    name: Optional[str] = None
    description: Optional[str] = None
    paths: Optional[List[str]] = None
    enabled: Optional[bool] = None
    schedule_type: Optional[str] = None
    interval_minutes: Optional[int] = None
    retention_count: Optional[int] = None
    include_globs: Optional[List[str]] = None
    exclude_globs: Optional[List[str]] = None


class RunBackupRequest(BaseModel):
    """Request body for running a backup."""
    host_id: int = Field(..., description="Host to backup")
    plan_id: int = Field(..., description="Backup plan to execute")
    run_id: Optional[int] = Field(None, description="Associated simulation run")
    dry_run: bool = Field(default=False, description="Simulate without changes")


class RunRestoreRequest(BaseModel):
    """Request body for running a restore."""
    host_id: int = Field(..., description="Host to restore")
    plan_id: int = Field(..., description="Backup plan")
    snapshot_id: str = Field(default="latest", description="Snapshot ID or 'latest'")
    restore_mode: str = Field(default="in_place", description="in_place or restore_to_new_folder")
    target_override_path: Optional[str] = Field(None, description="Target path for restore_to_new_folder")
    dry_run: bool = Field(default=False, description="Simulate without changes")


# =============================================================================
# ROLE-BASED ACCESS HELPERS
# =============================================================================

def require_admin_or_ir_lead(user):
    """Check if user has admin or IR lead role."""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Check role - allow ADMIN or SENIOR_ANALYST (as IR_LEAD equivalent)
    allowed_roles = [UserRole.ADMIN, UserRole.SENIOR_ANALYST]
    if hasattr(user, 'role') and user.role not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Only Admin or IR Lead can perform this action"
        )
    return user


# =============================================================================
# BACKUP PLANS API (NEW)
# =============================================================================

@router.post("/plans", response_model=dict)
def create_plan(
    request: BackupPlanCreate,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Create a new backup plan. Requires Admin or IR Lead role."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    require_admin_or_ir_lead(user)
    
    # Validate paths are in allowed directories
    allowed_prefixes = ["C:\\RansomTest", "C:\\target_data", "C:\\ProgramData\\RansomRun"]
    for path in request.paths:
        path_upper = path.upper()
        if not any(path_upper.startswith(prefix.upper()) for prefix in allowed_prefixes):
            raise HTTPException(
                status_code=400,
                detail=f"Path '{path}' is not in allowed backup directories. Allowed: {allowed_prefixes}"
            )
    
    # Parse enums
    try:
        scope = BackupScopeType(request.scope_type)
        schedule = BackupScheduleType(request.schedule_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    plan = create_backup_plan(
        db=db,
        name=request.name,
        paths=request.paths,
        description=request.description,
        scope_type=scope,
        schedule_type=schedule,
        interval_minutes=request.interval_minutes,
        retention_count=request.retention_count,
        include_globs=request.include_globs,
        exclude_globs=request.exclude_globs,
        storage_base_path=request.storage_base_path,
        network_share_path=request.network_share_path,
        created_by_user_id=user.id if hasattr(user, 'id') else None
    )
    
    return {
        "success": True,
        "message": f"Backup plan '{plan.name}' created",
        "plan_id": plan.id,
        "plan": _serialize_plan(plan)
    }


@router.get("/plans")
def list_plans(
    enabled_only: bool = Query(False, description="Only show enabled plans"),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """List all backup plans."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    plans = get_all_backup_plans(db, enabled_only=enabled_only)
    return {
        "success": True,
        "count": len(plans),
        "plans": [_serialize_plan(p) for p in plans]
    }


@router.get("/plans/{plan_id}")
def get_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get a specific backup plan."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    plan = get_backup_plan(db, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Backup plan not found")
    
    return {
        "success": True,
        "plan": _serialize_plan(plan)
    }


@router.put("/plans/{plan_id}")
def update_plan(
    plan_id: int,
    request: BackupPlanUpdate,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Update a backup plan. Requires Admin or IR Lead role."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    require_admin_or_ir_lead(user)
    
    update_data = request.dict(exclude_unset=True)
    
    # Handle paths rename
    if 'paths' in update_data:
        update_data['paths_json'] = update_data.pop('paths')
    
    # Handle schedule_type enum
    if 'schedule_type' in update_data:
        try:
            update_data['schedule_type'] = BackupScheduleType(update_data['schedule_type'])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    plan = update_backup_plan(db, plan_id, **update_data)
    if not plan:
        raise HTTPException(status_code=404, detail="Backup plan not found")
    
    return {
        "success": True,
        "message": f"Backup plan '{plan.name}' updated",
        "plan": _serialize_plan(plan)
    }


@router.delete("/plans/{plan_id}")
def delete_plan(
    plan_id: int,
    hard_delete: bool = Query(False, description="Permanently delete instead of disable"),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Delete or disable a backup plan. Requires Admin or IR Lead role."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    require_admin_or_ir_lead(user)
    
    success = delete_backup_plan(db, plan_id, soft=not hard_delete)
    if not success:
        raise HTTPException(status_code=404, detail="Backup plan not found")
    
    return {
        "success": True,
        "message": "Backup plan deleted" if hard_delete else "Backup plan disabled"
    }


# =============================================================================
# BACKUP/RESTORE EXECUTION API (NEW)
# =============================================================================

@router.post("/run/backup")
def run_backup(
    request: RunBackupRequest,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Execute a backup job. Creates agent task."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    # Validate host exists
    host = db.query(Host).filter(Host.id == request.host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Validate plan exists
    plan = get_backup_plan(db, request.plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Backup plan not found")
    
    if not plan.enabled:
        raise HTTPException(status_code=400, detail="Backup plan is disabled")
    
    # Create backup job record
    job = create_backup_job(
        db=db,
        host_id=request.host_id,
        job_type=BackupJobType.BACKUP,
        plan_id=request.plan_id,
        run_id=request.run_id,
        dry_run=request.dry_run,
        requested_by_user_id=user.id if hasattr(user, 'id') else None
    )
    
    # Build task parameters for agent
    task_params = {
        "job_id": job.id,
        "plan_id": plan.id,
        "plan_name": plan.name,
        "paths": plan.paths_json,
        "include_globs": plan.include_globs,
        "exclude_globs": plan.exclude_globs,
        "retention_count": plan.retention_count,
        "storage_base_path": plan.storage_base_path or "C:\\ProgramData\\RansomRun\\backups",
        "network_share_path": plan.network_share_path,
        "dry_run": request.dry_run,
        "run_id": request.run_id
    }
    
    # Create agent task
    task = create_backup_task(db, request.host_id, "backup_create", task_params)
    
    # Update job with task reference
    job.task_id = task.id
    db.commit()
    
    return {
        "success": True,
        "message": f"Backup job created{' (DRY RUN)' if request.dry_run else ''}",
        "job_id": job.id,
        "task_id": task.id,
        "plan_name": plan.name,
        "paths": plan.paths_json,
        "dry_run": request.dry_run
    }


@router.post("/run/restore")
def run_restore(
    request: RunRestoreRequest,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Execute a restore job. Requires Admin or IR Lead role."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    require_admin_or_ir_lead(user)
    
    # Validate host exists
    host = db.query(Host).filter(Host.id == request.host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Validate plan exists
    plan = get_backup_plan(db, request.plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Backup plan not found")
    
    # Get snapshot
    if request.snapshot_id == "latest":
        snapshot = get_latest_new_snapshot(db, request.host_id, request.plan_id)
        if not snapshot:
            raise HTTPException(status_code=404, detail="No snapshots found for this host/plan")
    else:
        try:
            snapshot_id = int(request.snapshot_id)
            snapshot = get_backup_snapshot(db, snapshot_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid snapshot_id")
        
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
    
    # Parse restore mode
    try:
        restore_mode = RestoreMode(request.restore_mode)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid restore_mode. Use 'in_place' or 'restore_to_new_folder'")
    
    # Create restore job record
    job = create_backup_job(
        db=db,
        host_id=request.host_id,
        job_type=BackupJobType.RESTORE,
        plan_id=request.plan_id,
        snapshot_id=snapshot.id,
        dry_run=request.dry_run,
        restore_mode=restore_mode,
        target_override_path=request.target_override_path,
        requested_by_user_id=user.id if hasattr(user, 'id') else None
    )
    
    # Get snapshot path (handle both new and legacy field names)
    snapshot_path = getattr(snapshot, 'storage_path', None) or getattr(snapshot, 'backup_path', None)
    source_paths = getattr(snapshot, 'source_paths_json', None) or plan.paths_json
    snapshot_time = getattr(snapshot, 'snapshot_time', None) or getattr(snapshot, 'created_at', None)
    
    if not snapshot_path:
        raise HTTPException(status_code=400, detail="Snapshot has no storage path")
    
    # Build task parameters for agent
    task_params = {
        "job_id": job.id,
        "snapshot_id": snapshot.id,
        "snapshot_path": snapshot_path,
        "source_paths": source_paths,
        "restore_mode": request.restore_mode,
        "target_override_path": request.target_override_path,
        "dry_run": request.dry_run
    }
    
    # Create agent task
    task = create_backup_task(db, request.host_id, "backup_restore", task_params)
    
    # Update job with task reference
    job.task_id = task.id
    db.commit()
    
    return {
        "success": True,
        "message": f"Restore job created{' (DRY RUN)' if request.dry_run else ''}",
        "job_id": job.id,
        "task_id": task.id,
        "snapshot_id": snapshot.id,
        "snapshot_time": snapshot_time.isoformat() if snapshot_time else None,
        "restore_mode": request.restore_mode,
        "dry_run": request.dry_run
    }


# =============================================================================
# JOBS & SNAPSHOTS API (NEW)
# =============================================================================

@router.get("/jobs")
def list_jobs(
    host_id: Optional[int] = Query(None),
    run_id: Optional[int] = Query(None),
    plan_id: Optional[int] = Query(None),
    job_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """List backup/restore jobs with filters."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    # Parse enums if provided
    jt = BackupJobType(job_type) if job_type else None
    st = BackupJobStatus(status) if status else None
    
    jobs = get_backup_jobs(db, host_id, run_id, plan_id, jt, st, limit)
    
    return {
        "success": True,
        "count": len(jobs),
        "jobs": [_serialize_job(j) for j in jobs]
    }


@router.get("/jobs/{job_id}")
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get details of a specific job."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    job = get_backup_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return {
        "success": True,
        "job": _serialize_job(job, include_details=True)
    }


@router.get("/snapshots")
def list_snapshots_new(
    host_id: Optional[int] = Query(None),
    plan_id: Optional[int] = Query(None),
    run_id: Optional[int] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """List backup snapshots with filters."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    snapshots = get_backup_snapshots(db, host_id, plan_id, run_id, limit=limit)
    
    return {
        "success": True,
        "count": len(snapshots),
        "snapshots": [_serialize_snapshot(s) for s in snapshots]
    }


@router.get("/metrics")
def get_metrics(
    host_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get RTO/RPO metrics for reporting."""
    if not NEW_BACKUP_MODELS_AVAILABLE:
        raise HTTPException(status_code=501, detail="New backup models not available")
    
    metrics = get_rto_rpo_metrics(db, host_id)
    
    return {
        "success": True,
        "metrics": metrics
    }


# =============================================================================
# SERIALIZATION HELPERS
# =============================================================================

def _serialize_plan(plan: "BackupPlan") -> dict:
    """Serialize a BackupPlan to dict."""
    return {
        "id": plan.id,
        "name": plan.name,
        "description": plan.description,
        "scope_type": plan.scope_type.value if plan.scope_type else None,
        "enabled": plan.enabled,
        "paths": plan.paths_json,
        "include_globs": plan.include_globs,
        "exclude_globs": plan.exclude_globs,
        "schedule_type": plan.schedule_type.value if plan.schedule_type else None,
        "interval_minutes": plan.interval_minutes,
        "retention_count": plan.retention_count,
        "storage_base_path": plan.storage_base_path,
        "network_share_path": plan.network_share_path,
        "created_at": plan.created_at.isoformat() if plan.created_at else None,
        "updated_at": plan.updated_at.isoformat() if plan.updated_at else None
    }


def _serialize_job(job: "BackupJob", include_details: bool = False) -> dict:
    """Serialize a BackupJob to dict."""
    result = {
        "id": job.id,
        "host_id": job.host_id,
        "plan_id": job.plan_id,
        "run_id": job.run_id,
        "snapshot_id": job.snapshot_id,
        "task_id": job.task_id,
        "job_type": job.job_type.value if job.job_type else None,
        "status": job.status.value if job.status else None,
        "dry_run": job.dry_run,
        "restore_mode": job.restore_mode.value if job.restore_mode else None,
        "target_override_path": job.target_override_path,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "ended_at": job.ended_at.isoformat() if job.ended_at else None,
        "duration_seconds": job.duration_seconds,
        "created_at": job.created_at.isoformat() if job.created_at else None
    }
    
    if include_details:
        result["details"] = job.details_json
        result["stdout"] = job.stdout
        result["stderr"] = job.stderr
    
    return result


def _serialize_snapshot(snapshot) -> dict:
    """Serialize a BackupSnapshot to dict."""
    # Handle integrity_status - could be enum or string
    integrity_status = None
    if hasattr(snapshot, 'integrity_status') and snapshot.integrity_status:
        if hasattr(snapshot.integrity_status, 'value'):
            integrity_status = snapshot.integrity_status.value
        else:
            integrity_status = str(snapshot.integrity_status)
    
    return {
        "id": snapshot.id,
        "host_id": snapshot.host_id,
        "plan_id": getattr(snapshot, 'plan_id', None),
        "job_id": getattr(snapshot, 'job_id', None),
        "run_id": getattr(snapshot, 'run_id', None),
        "snapshot_time": snapshot.snapshot_time.isoformat() if getattr(snapshot, 'snapshot_time', None) else (snapshot.created_at.isoformat() if snapshot.created_at else None),
        "storage_path": getattr(snapshot, 'storage_path', None) or getattr(snapshot, 'backup_path', None),
        "file_count": getattr(snapshot, 'file_count', None) or getattr(snapshot, 'total_files', 0),
        "total_bytes": getattr(snapshot, 'total_bytes', None) or getattr(snapshot, 'total_size_bytes', 0),
        "folder_count": getattr(snapshot, 'folder_count', 0),
        "manifest_path": getattr(snapshot, 'manifest_path', None),
        "integrity_status": integrity_status,
        "integrity_checked_at": snapshot.integrity_checked_at.isoformat() if getattr(snapshot, 'integrity_checked_at', None) else None,
        "source_paths": snapshot.source_paths_json,
        "notes": snapshot.notes,
        "created_at": snapshot.created_at.isoformat() if snapshot.created_at else None
    }


# =============================================================================
# LEGACY API (BACKWARDS COMPATIBILITY)
# =============================================================================


@router.post("/snapshot/{host_id}")
def create_backup_snapshot(
    host_id: int,
    snapshot_type: str = "FILE_LEVEL",
    dry_run: bool = False,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Create a backup snapshot for a host."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    engine = BackupEngine(db)
    result = engine.create_snapshot(
        host=host,
        snapshot_type=snapshot_type,
        triggered_by="manual",
        dry_run=dry_run
    )
    
    return result


@router.get("/snapshots/{host_id}")
def list_snapshots(
    host_id: int,
    limit: int = 50,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """List backup snapshots for a host."""
    engine = BackupEngine(db)
    snapshots = engine.get_snapshots(host_id=host_id, status=status, limit=limit)
    
    return [
        {
            "id": s.id,
            "snapshot_name": s.snapshot_name,
            "snapshot_type": s.snapshot_type,
            "status": s.status.value if hasattr(s.status, 'value') else s.status,
            "total_files": s.total_files,
            "total_size_bytes": s.total_size_bytes,
            "files_backed_up": s.files_backed_up,
            "files_failed": s.files_failed,
            "manifest_hash": s.manifest_hash,
            "is_verified": s.is_verified,
            "triggered_by": s.triggered_by,
            "created_at": s.created_at.isoformat(),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "uploaded": s.uploaded
        }
        for s in snapshots
    ]


@router.get("/snapshot/{snapshot_id}")
def get_snapshot_details(
    snapshot_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get detailed information about a backup snapshot."""
    snapshot = db.query(BackupSnapshot).filter(
        BackupSnapshot.id == snapshot_id
    ).first()
    
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    
    return {
        "id": snapshot.id,
        "host_id": snapshot.host_id,
        "snapshot_name": snapshot.snapshot_name,
        "snapshot_type": snapshot.snapshot_type,
        "status": snapshot.status.value if hasattr(snapshot.status, 'value') else snapshot.status,
        "backup_path": snapshot.backup_path,
        "total_files": snapshot.total_files,
        "total_size_bytes": snapshot.total_size_bytes,
        "files_backed_up": snapshot.files_backed_up,
        "files_failed": snapshot.files_failed,
        "manifest_hash": snapshot.manifest_hash,
        "is_verified": snapshot.is_verified,
        "triggered_by": snapshot.triggered_by,
        "alert_id": snapshot.alert_id,
        "created_at": snapshot.created_at.isoformat(),
        "started_at": snapshot.started_at.isoformat() if snapshot.started_at else None,
        "completed_at": snapshot.completed_at.isoformat() if snapshot.completed_at else None,
        "uploaded": snapshot.uploaded,
        "upload_path": snapshot.upload_path,
        "files": [
            {
                "id": f.id,
                "original_path": f.original_path,
                "backup_path": f.backup_path,
                "file_size_bytes": f.file_size_bytes,
                "file_hash": f.file_hash,
                "backed_up": f.backed_up,
                "error_message": f.error_message
            }
            for f in snapshot.files[:100]  # Limit to first 100 files
        ]
    }


@router.post("/restore/{snapshot_id}")
def restore_snapshot(
    snapshot_id: int,
    restore_type: str = "FULL",
    target_path: Optional[str] = None,
    dry_run: bool = False,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Restore from a backup snapshot."""
    engine = BackupEngine(db)
    result = engine.restore_snapshot(
        snapshot_id=snapshot_id,
        restore_type=restore_type,
        target_path=target_path,
        dry_run=dry_run,
        initiated_by_user=user.email
    )
    
    return result


@router.get("/restore/events/{host_id}")
def list_restore_events(
    host_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """List restore events for a host."""
    events = db.query(RestoreEvent).filter(
        RestoreEvent.host_id == host_id
    ).order_by(RestoreEvent.created_at.desc()).limit(limit).all()
    
    return [
        {
            "id": e.id,
            "snapshot_id": e.snapshot_id,
            "restore_type": e.restore_type,
            "status": e.status.value if hasattr(e.status, 'value') else e.status,
            "files_to_restore": e.files_to_restore,
            "files_restored": e.files_restored,
            "files_failed": e.files_failed,
            "files_missing": e.files_missing,
            "hash_verification_passed": e.hash_verification_passed,
            "hash_verification_failed": e.hash_verification_failed,
            "triggered_by": e.triggered_by,
            "initiated_by_user": e.initiated_by_user,
            "created_at": e.created_at.isoformat(),
            "started_at": e.started_at.isoformat() if e.started_at else None,
            "completed_at": e.completed_at.isoformat() if e.completed_at else None,
            "result_message": e.result_message
        }
        for e in events
    ]


@router.post("/verify/{snapshot_id}")
def verify_snapshot_integrity(
    snapshot_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Verify integrity of a backup snapshot."""
    engine = BackupEngine(db)
    result = engine.verify_snapshot_integrity(snapshot_id)
    return result


@router.post("/upload")
async def upload_backup(
    file: UploadFile = File(...),
    snapshot_id: int = None,
    db: Session = Depends(get_db)
):
    """
    Upload backup snapshot from agent.
    This endpoint is called by agents to upload their backup files.
    """
    import os
    from pathlib import Path
    
    # Create upload directory if it doesn't exist
    upload_dir = Path("backups/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Save uploaded file
    file_path = upload_dir / file.filename
    
    try:
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)
        
        # Update snapshot record if snapshot_id provided
        if snapshot_id:
            snapshot = db.query(BackupSnapshot).filter(
                BackupSnapshot.id == snapshot_id
            ).first()
            
            if snapshot:
                snapshot.uploaded = True
                snapshot.upload_path = str(file_path)
                db.commit()
        
        return {
            "success": True,
            "message": "Backup uploaded successfully",
            "filename": file.filename,
            "size": len(contents),
            "path": str(file_path)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.get("/latest/{host_id}")
def get_latest_snapshot(
    host_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get the latest successful backup snapshot for a host."""
    engine = BackupEngine(db)
    snapshot = engine.get_latest_snapshot(host_id)
    
    if not snapshot:
        return {"success": False, "message": "No successful backup found"}
    
    return {
        "success": True,
        "snapshot": {
            "id": snapshot.id,
            "snapshot_name": snapshot.snapshot_name,
            "snapshot_type": snapshot.snapshot_type,
            "status": snapshot.status.value if hasattr(snapshot.status, 'value') else snapshot.status,
            "total_files": snapshot.total_files,
            "total_size_bytes": snapshot.total_size_bytes,
            "files_backed_up": snapshot.files_backed_up,
            "created_at": snapshot.created_at.isoformat(),
            "completed_at": snapshot.completed_at.isoformat() if snapshot.completed_at else None
        }
    }
