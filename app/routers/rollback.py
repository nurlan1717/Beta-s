"""
AutoRollback API Endpoints

Provides REST API for creating, approving, and executing rollback plans.
All operations enforce safety constraints and audit logging.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from pydantic import BaseModel

from ..database import get_db
from ..models import Host, RollbackPlan, RollbackPlanStatus
from ..services.rollback_engine import RollbackEngine, DEFAULT_SAFE_PATHS
from ..deps.auth import require_user

router = APIRouter(prefix="/api/rollback", tags=["rollback"])


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

class CreateSnapshotRequest(BaseModel):
    host_id: int
    safe_paths: Optional[List[str]] = None
    label: Optional[str] = None
    run_id: Optional[int] = None


class CreatePlanRequest(BaseModel):
    host_id: int
    run_id: Optional[int] = None
    snapshot_id: Optional[int] = None
    safe_paths: Optional[List[str]] = None
    conflict_policy: str = "QUARANTINE"
    cleanup_extensions: Optional[List[str]] = None
    dry_run: bool = False
    require_approval: bool = True


class ApprovePlanRequest(BaseModel):
    approved_by: Optional[str] = None


class ExecutePlanRequest(BaseModel):
    force: bool = False


class ProcessResultRequest(BaseModel):
    file_results: List[dict]


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/snapshot/create")
def create_snapshot(
    request: CreateSnapshotRequest,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Create a baseline snapshot for a host.
    
    This creates an agent task to backup files in the safe paths.
    The snapshot can later be used for rollback operations.
    """
    from ..models import Host, Task, BackupSnapshot, BackupStatus, RunEvent, EventType
    from datetime import datetime
    
    # Validate host
    host = db.query(Host).filter(Host.id == request.host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Determine safe paths
    safe_paths = request.safe_paths or DEFAULT_SAFE_PATHS
    
    # Generate snapshot name
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    label = request.label or "baseline"
    snapshot_name = f"{label}_{host.agent_id}_{timestamp}"
    
    # Create snapshot record
    snapshot = BackupSnapshot(
        host_id=host.id,
        snapshot_name=snapshot_name,
        snapshot_type="BASELINE",
        status=BackupStatus.PENDING,
        triggered_by=user.email if hasattr(user, 'email') else "system",
        created_at=datetime.utcnow(),
        total_files=0,
        files_backed_up=0,
        files_failed=0
    )
    db.add(snapshot)
    db.flush()
    
    # Create agent task
    task = Task(
        host_id=host.id,
        run_id=request.run_id,
        type="backup_create_snapshot",
        parameters={
            "snapshot_id": snapshot.id,
            "snapshot_name": snapshot_name,
            "safe_paths": safe_paths,
            "label": label
        },
        status="PENDING"
    )
    db.add(task)
    db.flush()
    
    # Create timeline event
    if request.run_id:
        event = RunEvent(
            run_id=request.run_id,
            host_id=host.id,
            event_type=EventType.SNAPSHOT_CREATED,
            timestamp=datetime.utcnow(),
            details={
                "snapshot_id": snapshot.id,
                "snapshot_name": snapshot_name,
                "safe_paths": safe_paths,
                "task_id": task.id
            }
        )
        db.add(event)
    
    db.commit()
    
    return {
        "success": True,
        "message": f"Snapshot creation task queued",
        "data": {
            "snapshot_id": snapshot.id,
            "snapshot_name": snapshot_name,
            "task_id": task.id,
            "status": "PENDING"
        }
    }


@router.get("/snapshots")
def list_snapshots(
    host_id: int,
    limit: int = Query(20, le=100),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """List snapshots for a host."""
    from ..models import BackupSnapshot
    
    snapshots = db.query(BackupSnapshot).filter(
        BackupSnapshot.host_id == host_id
    ).order_by(BackupSnapshot.created_at.desc()).limit(limit).all()
    
    return {
        "host_id": host_id,
        "total": len(snapshots),
        "snapshots": [
            {
                "id": s.id,
                "name": s.snapshot_name,
                "type": s.snapshot_type,
                "status": s.status.value if s.status else "UNKNOWN",
                "total_files": s.total_files,
                "files_backed_up": s.files_backed_up,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None
            }
            for s in snapshots
        ]
    }


@router.post("/snapshot/complete")
def complete_snapshot(
    snapshot_id: int,
    manifest: dict,
    total_files: int,
    files_backed_up: int,
    files_failed: int,
    db: Session = Depends(get_db)
):
    """
    Callback from agent when snapshot is complete.
    Updates the snapshot record with results.
    """
    from ..models import BackupSnapshot, BackupFile, BackupStatus
    from datetime import datetime
    
    snapshot = db.query(BackupSnapshot).filter(BackupSnapshot.id == snapshot_id).first()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    
    # Update snapshot record
    snapshot.status = BackupStatus.COMPLETED if files_failed == 0 else BackupStatus.PARTIAL
    snapshot.completed_at = datetime.utcnow()
    snapshot.total_files = total_files
    snapshot.files_backed_up = files_backed_up
    snapshot.files_failed = files_failed
    snapshot.manifest_hash = manifest.get("created_at", "")
    
    # Store backup directory in snapshot
    backup_directory = manifest.get("backup_directory")
    if backup_directory:
        snapshot.backup_path = backup_directory
    
    # Create backup file records from manifest
    for file_info in manifest.get("files", []):
        if file_info.get("backed_up"):
            backup_file = BackupFile(
                snapshot_id=snapshot.id,
                original_path=file_info.get("path"),
                backup_path=file_info.get("backup_path", file_info.get("path")),  # Use actual backup path
                file_size_bytes=file_info.get("size", 0),
                file_hash=file_info.get("hash"),
                backed_up=True,
                backed_up_at=datetime.utcnow()
            )
            db.add(backup_file)
    
    db.commit()
    
    return {
        "success": True,
        "snapshot_id": snapshot_id,
        "status": snapshot.status.value,
        "backup_directory": backup_directory
    }


@router.post("/plan")
def create_rollback_plan(
    request: CreatePlanRequest,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Create a rollback plan for a host.
    
    The plan analyzes the backup snapshot and determines which files
    can be safely restored based on the configured safe paths.
    
    Safety constraints:
    - Only files in safe_paths will be restored
    - System directories are always blocked
    - Plan requires approval by default
    """
    engine = RollbackEngine(db)
    
    result = engine.create_plan(
        host_id=request.host_id,
        run_id=request.run_id,
        snapshot_id=request.snapshot_id,
        safe_paths=request.safe_paths,
        conflict_policy=request.conflict_policy,
        cleanup_extensions=request.cleanup_extensions,
        dry_run=request.dry_run,
        require_approval=request.require_approval,
        created_by=user.email
    )
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    
    return result


@router.post("/plan/{plan_id}/approve")
def approve_rollback_plan(
    plan_id: int,
    request: ApprovePlanRequest,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Approve a rollback plan for execution.
    
    Only plans in PENDING_APPROVAL status can be approved.
    """
    engine = RollbackEngine(db)
    
    approved_by = request.approved_by or user.email
    result = engine.approve_plan(plan_id, approved_by)
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    
    return result


@router.post("/execute/{plan_id}")
def execute_rollback_plan(
    plan_id: int,
    dry_run: bool = Query(False, description="Simulate execution without making changes"),
    force: bool = Query(False, description="Force execution even if already executed"),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Execute a rollback plan.
    
    Creates agent tasks to restore files from the backup snapshot.
    
    Args:
        plan_id: ID of the plan to execute
        dry_run: If true, simulates execution without making changes
        force: If true, allows re-execution of completed plans
    """
    engine = RollbackEngine(db)
    
    # If dry_run requested, update plan
    if dry_run:
        plan = db.query(RollbackPlan).filter(RollbackPlan.id == plan_id).first()
        if plan:
            plan.dry_run = True
            db.commit()
    
    result = engine.execute_plan(plan_id, force=force)
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    
    return result


@router.get("/plans")
def list_rollback_plans(
    host_id: Optional[int] = Query(None, description="Filter by host ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    List rollback plans with optional filters.
    """
    engine = RollbackEngine(db)
    plans = engine.list_plans(host_id=host_id, status=status, limit=limit)
    return {"plans": plans, "count": len(plans)}


@router.get("/plans/{plan_id}")
def get_rollback_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Get detailed information about a rollback plan.
    """
    engine = RollbackEngine(db)
    plan = engine.get_plan(plan_id)
    
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    return plan


@router.get("/reports/{plan_id}")
def get_rollback_report(
    plan_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Get the execution report for a rollback plan.
    """
    engine = RollbackEngine(db)
    report = engine.get_report(plan_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return report


@router.post("/plans/{plan_id}/cancel")
def cancel_rollback_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Cancel a pending rollback plan.
    """
    engine = RollbackEngine(db)
    result = engine.cancel_plan(plan_id, user.email)
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    
    return result


@router.delete("/plans/{plan_id}")
def delete_rollback_plan(
    plan_id: int,
    force: bool = Query(False, description="Force delete even if executing"),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Delete a rollback plan.
    
    Plans can only be deleted if they are not currently executing (unless force=true).
    """
    from ..models import RollbackPlan, RollbackFileAction, RollbackReport
    
    plan = db.query(RollbackPlan).filter(RollbackPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    
    # Don't allow deleting plans that are currently executing (unless forced)
    if plan.status == RollbackPlanStatus.EXECUTING and not force:
        raise HTTPException(status_code=400, detail="Cannot delete a plan that is currently executing. Use force=true to override.")
    
    # Delete related file actions
    db.query(RollbackFileAction).filter(RollbackFileAction.plan_id == plan_id).delete()
    
    # Delete related reports
    db.query(RollbackReport).filter(RollbackReport.plan_id == plan_id).delete()
    
    # Delete the plan
    db.delete(plan)
    db.commit()
    
    return {"success": True, "message": f"Plan #{plan_id} deleted successfully"}


@router.post("/result/{plan_id}")
def process_rollback_result(
    plan_id: int,
    request: ProcessResultRequest,
    db: Session = Depends(get_db)
):
    """
    Process execution results from agent.
    Called by agent after completing rollback task.
    """
    engine = RollbackEngine(db)
    result = engine.process_execution_result(plan_id, {"file_results": request.file_results})
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    
    return result


@router.get("/config")
def get_rollback_config(
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Get current rollback configuration and defaults.
    """
    from ..models import SystemConfig
    
    # Get global settings
    global_enabled = db.query(SystemConfig).filter(
        SystemConfig.key == "autorollback_enabled"
    ).first()
    
    return {
        "global_enabled": global_enabled.value.lower() == "true" if global_enabled else False,
        "default_safe_paths": DEFAULT_SAFE_PATHS,
        "default_conflict_policy": "QUARANTINE",
        "default_cleanup_extensions": [".locked", ".encrypted", ".dwcrypt"],
        "require_approval_default": True
    }


@router.get("/host/{host_id}/status")
def get_host_rollback_status(
    host_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Get rollback status and availability for a host.
    """
    engine = RollbackEngine(db)
    
    # Check if host exists
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Check if autorollback is enabled
    enabled, reason = engine.check_host_autorollback_enabled(host_id)
    
    # Get latest snapshot
    snapshot = engine.get_latest_snapshot(host_id)
    
    # Get active plans
    active_plan = db.query(RollbackPlan).filter(
        RollbackPlan.host_id == host_id,
        RollbackPlan.status.in_([
            RollbackPlanStatus.PENDING_APPROVAL,
            RollbackPlanStatus.APPROVED,
            RollbackPlanStatus.EXECUTING
        ])
    ).first()
    
    # Get recent completed plans
    recent_plans = engine.list_plans(host_id=host_id, limit=5)
    
    return {
        "host_id": host_id,
        "host_name": host.name,
        "autorollback_enabled": enabled,
        "autorollback_reason": reason,
        "has_snapshot": snapshot is not None,
        "latest_snapshot": {
            "id": snapshot.id,
            "name": snapshot.snapshot_name,
            "created_at": snapshot.created_at.isoformat(),
            "total_files": snapshot.total_files
        } if snapshot else None,
        "active_plan": {
            "id": active_plan.id,
            "status": active_plan.status.value,
            "created_at": active_plan.created_at.isoformat()
        } if active_plan else None,
        "recent_plans": recent_plans
    }
