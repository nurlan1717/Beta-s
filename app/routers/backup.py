"""Backup and recovery API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from ..models import Host, BackupSnapshot, RestoreEvent
from ..services.backup_engine import BackupEngine
from ..deps.auth import require_user

router = APIRouter(prefix="/api/backup", tags=["backup"])


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
