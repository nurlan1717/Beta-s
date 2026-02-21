"""CRUD operations for Backup & Restore feature.

Provides database operations for backup plans, jobs, and snapshots.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_

from .models_backup import (
    BackupPlan, BackupJob,
    BackupScopeType, BackupScheduleType, BackupJobType,
    BackupJobStatus, BackupIntegrityStatus, RestoreMode
)
from .models import Host, Run, Task, TaskStatus, BackupSnapshot


# =============================================================================
# BACKUP PLAN CRUD
# =============================================================================

def create_backup_plan(
    db: Session,
    name: str,
    paths: List[str],
    description: str = None,
    scope_type: BackupScopeType = BackupScopeType.FOLDER,
    schedule_type: BackupScheduleType = BackupScheduleType.MANUAL,
    interval_minutes: int = None,
    retention_count: int = 5,
    include_globs: List[str] = None,
    exclude_globs: List[str] = None,
    storage_base_path: str = None,
    network_share_path: str = None,
    created_by_user_id: int = None
) -> BackupPlan:
    """Create a new backup plan."""
    plan = BackupPlan(
        name=name,
        description=description,
        scope_type=scope_type,
        enabled=True,
        paths_json=paths,
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        schedule_type=schedule_type,
        interval_minutes=interval_minutes,
        retention_count=retention_count,
        storage_base_path=storage_base_path,
        network_share_path=network_share_path,
        created_by_user_id=created_by_user_id
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


def get_backup_plan(db: Session, plan_id: int) -> Optional[BackupPlan]:
    """Get a backup plan by ID."""
    return db.query(BackupPlan).filter(BackupPlan.id == plan_id).first()


def get_backup_plan_by_name(db: Session, name: str) -> Optional[BackupPlan]:
    """Get a backup plan by name."""
    return db.query(BackupPlan).filter(BackupPlan.name == name).first()


def get_all_backup_plans(db: Session, enabled_only: bool = False) -> List[BackupPlan]:
    """Get all backup plans."""
    query = db.query(BackupPlan)
    if enabled_only:
        query = query.filter(BackupPlan.enabled == True)
    return query.order_by(BackupPlan.name).all()


def get_pre_simulation_plans(db: Session) -> List[BackupPlan]:
    """Get all enabled plans with pre_simulation schedule."""
    return db.query(BackupPlan).filter(
        BackupPlan.enabled == True,
        BackupPlan.schedule_type == BackupScheduleType.PRE_SIMULATION
    ).all()


def update_backup_plan(
    db: Session,
    plan_id: int,
    **kwargs
) -> Optional[BackupPlan]:
    """Update a backup plan."""
    plan = get_backup_plan(db, plan_id)
    if not plan:
        return None
    
    for key, value in kwargs.items():
        if hasattr(plan, key):
            setattr(plan, key, value)
    
    plan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(plan)
    return plan


def delete_backup_plan(db: Session, plan_id: int, soft: bool = True) -> bool:
    """Delete or disable a backup plan."""
    plan = get_backup_plan(db, plan_id)
    if not plan:
        return False
    
    if soft:
        plan.enabled = False
        plan.updated_at = datetime.utcnow()
    else:
        db.delete(plan)
    
    db.commit()
    return True


# =============================================================================
# BACKUP JOB CRUD
# =============================================================================

def create_backup_job(
    db: Session,
    host_id: int,
    job_type: BackupJobType,
    plan_id: int = None,
    run_id: int = None,
    snapshot_id: int = None,
    dry_run: bool = False,
    restore_mode: RestoreMode = None,
    target_override_path: str = None,
    requested_by_user_id: int = None
) -> BackupJob:
    """Create a new backup or restore job."""
    job = BackupJob(
        host_id=host_id,
        plan_id=plan_id,
        run_id=run_id,
        snapshot_id=snapshot_id,
        job_type=job_type,
        status=BackupJobStatus.PENDING,
        dry_run=dry_run,
        restore_mode=restore_mode,
        target_override_path=target_override_path,
        requested_by_user_id=requested_by_user_id
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_backup_job(db: Session, job_id: int) -> Optional[BackupJob]:
    """Get a backup job by ID."""
    return db.query(BackupJob).filter(BackupJob.id == job_id).first()


def get_backup_jobs(
    db: Session,
    host_id: int = None,
    run_id: int = None,
    plan_id: int = None,
    job_type: BackupJobType = None,
    status: BackupJobStatus = None,
    limit: int = 50
) -> List[BackupJob]:
    """Get backup jobs with optional filters."""
    query = db.query(BackupJob)
    
    if host_id:
        query = query.filter(BackupJob.host_id == host_id)
    if run_id:
        query = query.filter(BackupJob.run_id == run_id)
    if plan_id:
        query = query.filter(BackupJob.plan_id == plan_id)
    if job_type:
        query = query.filter(BackupJob.job_type == job_type)
    if status:
        query = query.filter(BackupJob.status == status)
    
    return query.order_by(desc(BackupJob.created_at)).limit(limit).all()


def update_backup_job(
    db: Session,
    job_id: int,
    **kwargs
) -> Optional[BackupJob]:
    """Update a backup job."""
    job = get_backup_job(db, job_id)
    if not job:
        return None
    
    for key, value in kwargs.items():
        if hasattr(job, key):
            setattr(job, key, value)
    
    db.commit()
    db.refresh(job)
    return job


def start_backup_job(db: Session, job_id: int, task_id: int = None) -> Optional[BackupJob]:
    """Mark a backup job as running."""
    return update_backup_job(
        db, job_id,
        status=BackupJobStatus.RUNNING,
        started_at=datetime.utcnow(),
        task_id=task_id
    )


def complete_backup_job(
    db: Session,
    job_id: int,
    success: bool,
    details: Dict[str, Any] = None,
    stdout: str = None,
    stderr: str = None
) -> Optional[BackupJob]:
    """Mark a backup job as completed."""
    job = get_backup_job(db, job_id)
    if not job:
        return None
    
    job.status = BackupJobStatus.SUCCESS if success else BackupJobStatus.FAILED
    job.ended_at = datetime.utcnow()
    
    if job.started_at:
        job.duration_seconds = (job.ended_at - job.started_at).total_seconds()
    
    job.details_json = details
    job.stdout = stdout
    job.stderr = stderr
    
    db.commit()
    db.refresh(job)
    return job


# =============================================================================
# BACKUP SNAPSHOT CRUD
# =============================================================================

def create_backup_snapshot(
    db: Session,
    host_id: int,
    plan_id: int,
    storage_path: str,
    file_count: int = 0,
    total_bytes: int = 0,
    folder_count: int = 0,
    manifest_path: str = None,
    source_paths: List[str] = None,
    job_id: int = None,
    run_id: int = None,
    notes: str = None
) -> BackupSnapshot:
    """Create a new backup snapshot record."""
    snapshot = BackupSnapshot(
        host_id=host_id,
        plan_id=plan_id,
        job_id=job_id,
        run_id=run_id,
        snapshot_time=datetime.utcnow(),
        storage_path=storage_path,
        file_count=file_count,
        total_bytes=total_bytes,
        folder_count=folder_count,
        manifest_path=manifest_path,
        source_paths_json=source_paths,
        notes=notes,
        integrity_status=BackupIntegrityStatus.UNCHECKED
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def get_backup_snapshot(db: Session, snapshot_id: int) -> Optional[BackupSnapshot]:
    """Get a backup snapshot by ID."""
    return db.query(BackupSnapshot).filter(
        BackupSnapshot.id == snapshot_id,
        BackupSnapshot.deleted == False
    ).first()


def get_backup_snapshots(
    db: Session,
    host_id: int = None,
    plan_id: int = None,
    run_id: int = None,
    include_deleted: bool = False,
    limit: int = 50
) -> List[BackupSnapshot]:
    """Get backup snapshots with optional filters."""
    query = db.query(BackupSnapshot)
    
    if not include_deleted:
        query = query.filter(BackupSnapshot.deleted == False)
    if host_id:
        query = query.filter(BackupSnapshot.host_id == host_id)
    if plan_id:
        query = query.filter(BackupSnapshot.plan_id == plan_id)
    if run_id:
        query = query.filter(BackupSnapshot.run_id == run_id)
    
    return query.order_by(desc(BackupSnapshot.snapshot_time)).limit(limit).all()


def get_latest_snapshot(
    db: Session,
    host_id: int,
    plan_id: int = None
) -> Optional[BackupSnapshot]:
    """Get the most recent snapshot for a host/plan."""
    query = db.query(BackupSnapshot).filter(
        BackupSnapshot.host_id == host_id,
        BackupSnapshot.deleted == False
    )
    if plan_id:
        query = query.filter(BackupSnapshot.plan_id == plan_id)
    
    return query.order_by(desc(BackupSnapshot.snapshot_time)).first()


def update_snapshot_integrity(
    db: Session,
    snapshot_id: int,
    status: BackupIntegrityStatus,
    errors: List[str] = None
) -> Optional[BackupSnapshot]:
    """Update snapshot integrity status."""
    snapshot = get_backup_snapshot(db, snapshot_id)
    if not snapshot:
        return None
    
    snapshot.integrity_status = status
    snapshot.integrity_checked_at = datetime.utcnow()
    snapshot.integrity_errors = errors
    
    db.commit()
    db.refresh(snapshot)
    return snapshot


def delete_backup_snapshot(db: Session, snapshot_id: int) -> bool:
    """Soft delete a backup snapshot."""
    snapshot = get_backup_snapshot(db, snapshot_id)
    if not snapshot:
        return False
    
    snapshot.deleted = True
    snapshot.deleted_at = datetime.utcnow()
    db.commit()
    return True


def get_snapshots_for_retention(
    db: Session,
    host_id: int,
    plan_id: int,
    keep_count: int
) -> List[BackupSnapshot]:
    """Get snapshots that should be deleted based on retention policy."""
    all_snapshots = db.query(BackupSnapshot).filter(
        BackupSnapshot.host_id == host_id,
        BackupSnapshot.plan_id == plan_id,
        BackupSnapshot.deleted == False
    ).order_by(desc(BackupSnapshot.snapshot_time)).all()
    
    # Return snapshots beyond retention count
    if len(all_snapshots) > keep_count:
        return all_snapshots[keep_count:]
    return []


# =============================================================================
# INTEGRATION HELPERS
# =============================================================================

def create_backup_task(
    db: Session,
    host_id: int,
    task_type: str,  # "backup_create" or "backup_restore"
    parameters: Dict[str, Any]
) -> Task:
    """Create an agent task for backup operations."""
    task = Task(
        host_id=host_id,
        type=task_type,
        parameters=parameters,
        status=TaskStatus.PENDING
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def get_rto_rpo_metrics(db: Session, host_id: int = None) -> Dict[str, Any]:
    """Calculate RTO/RPO metrics for reporting."""
    from sqlalchemy import func
    
    # Base query for restore jobs
    restore_query = db.query(BackupJob).filter(
        BackupJob.job_type == BackupJobType.RESTORE,
        BackupJob.status == BackupJobStatus.SUCCESS,
        BackupJob.duration_seconds.isnot(None)
    )
    
    if host_id:
        restore_query = restore_query.filter(BackupJob.host_id == host_id)
    
    # Calculate mean restore time (RTO proxy)
    restore_jobs = restore_query.all()
    if restore_jobs:
        total_duration = sum(j.duration_seconds for j in restore_jobs if j.duration_seconds)
        mean_rto = total_duration / len(restore_jobs) if restore_jobs else 0
    else:
        mean_rto = 0
    
    # Calculate success rate
    total_restore = db.query(BackupJob).filter(
        BackupJob.job_type == BackupJobType.RESTORE
    )
    if host_id:
        total_restore = total_restore.filter(BackupJob.host_id == host_id)
    total_restore_count = total_restore.count()
    
    success_restore = total_restore.filter(BackupJob.status == BackupJobStatus.SUCCESS).count()
    success_rate = (success_restore / total_restore_count * 100) if total_restore_count > 0 else 0
    
    # Get latest snapshot age (RPO proxy)
    latest_snapshot = db.query(BackupSnapshot).filter(
        BackupSnapshot.deleted == False
    )
    if host_id:
        latest_snapshot = latest_snapshot.filter(BackupSnapshot.host_id == host_id)
    latest_snapshot = latest_snapshot.order_by(desc(BackupSnapshot.snapshot_time)).first()
    
    rpo_seconds = 0
    if latest_snapshot:
        rpo_seconds = (datetime.utcnow() - latest_snapshot.snapshot_time).total_seconds()
    
    return {
        "mean_rto_seconds": round(mean_rto, 2),
        "mean_rto_display": f"{int(mean_rto // 60)}m {int(mean_rto % 60)}s" if mean_rto > 0 else "N/A",
        "recovery_success_rate": round(success_rate, 1),
        "total_restore_jobs": total_restore_count,
        "successful_restores": success_restore,
        "rpo_seconds": round(rpo_seconds, 0),
        "rpo_display": _format_duration(rpo_seconds) if rpo_seconds > 0 else "N/A",
        "latest_snapshot_time": latest_snapshot.snapshot_time.isoformat() if latest_snapshot else None
    }


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


# =============================================================================
# PRE-SIMULATION BACKUP INTEGRATION
# =============================================================================

def trigger_pre_simulation_backups(db: Session, host_id: int, run_id: int) -> list:
    """
    Trigger backup jobs for all enabled pre_simulation plans.
    Called when a new simulation run is created.
    
    Returns list of created job IDs.
    """
    from .models import Task, TaskStatus
    
    # Get all enabled pre-simulation plans
    plans = get_pre_simulation_plans(db)
    
    if not plans:
        return []
    
    job_ids = []
    
    for plan in plans:
        # Create backup job
        job = create_backup_job(
            db=db,
            host_id=host_id,
            job_type=BackupJobType.BACKUP,
            plan_id=plan.id,
            run_id=run_id,
            dry_run=False
        )
        
        # Build task parameters
        task_params = {
            "job_id": job.id,
            "plan_id": plan.id,
            "plan_name": plan.name,
            "paths": plan.paths_json,
            "include_globs": plan.include_globs,
            "exclude_globs": plan.exclude_globs,
            "retention_count": plan.retention_count,
            "storage_base_path": plan.storage_base_path or "C:\\ProgramData\\RansomRun\\backups",
            "dry_run": False,
            "run_id": run_id,
            "pre_simulation": True
        }
        
        # Create agent task
        task = create_backup_task(db, host_id, "backup_create", task_params)
        job.task_id = task.id
        db.commit()
        
        job_ids.append(job.id)
    
    return job_ids
