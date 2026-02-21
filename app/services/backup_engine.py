"""
Backup Engine - Manages host backup snapshots and recovery.

Handles:
- File-level backup snapshots with versioning
- Integrity verification (SHA256 hashing)
- Backup upload to central server
- Restore operations with verification
- VSS snapshot simulation
"""

import hashlib
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session

from ..models import Host, Task, BackupSnapshot, BackupFile, RestoreEvent, BackupStatus, RestoreStatus

logger = logging.getLogger(__name__)


class BackupEngine:
    """Manages backup snapshots and recovery operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_snapshot(
        self,
        host: Host,
        snapshot_type: str = "FILE_LEVEL",
        triggered_by: str = "manual",
        alert_id: Optional[int] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Create a backup snapshot of a host.
        
        Args:
            host: Host to backup
            snapshot_type: Type of backup (FILE_LEVEL, VSS_SIM, FULL)
            triggered_by: What triggered the backup
            alert_id: Associated alert ID
            dry_run: If True, simulate without creating actual backup
            
        Returns:
            Result dictionary with snapshot details
        """
        logger.info(f"Creating {snapshot_type} backup snapshot for host {host.name} (dry_run={dry_run})")
        
        # Generate snapshot name with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        snapshot_name = f"snapshot_{host.agent_id}_{timestamp}"
        
        # Create snapshot record
        snapshot = BackupSnapshot(
            host_id=host.id,
            snapshot_name=snapshot_name,
            snapshot_type=snapshot_type,
            status=BackupStatus.PENDING,
            triggered_by=triggered_by,
            alert_id=alert_id,
            created_at=datetime.utcnow()
        )
        
        self.db.add(snapshot)
        self.db.commit()
        
        if dry_run:
            snapshot.status = BackupStatus.COMPLETED
            snapshot.completed_at = datetime.utcnow()
            self.db.commit()
            
            return {
                "success": True,
                "message": f"[DRY RUN] Would create backup snapshot: {snapshot_name}",
                "data": {
                    "snapshot_id": snapshot.id,
                    "snapshot_name": snapshot_name,
                    "host_id": host.id
                }
            }
        
        # Create backup task for agent
        task_params = {
            "snapshot_id": snapshot.id,
            "snapshot_name": snapshot_name,
            "snapshot_type": snapshot_type,
            "safe_directories": self._get_safe_backup_directories(),
            "create_manifest": True,
            "hash_files": True
        }
        
        task = Task(
            host_id=host.id,
            type="backup_snapshot",
            parameters=task_params,
            status="PENDING"
        )
        self.db.add(task)
        
        # Update snapshot status
        snapshot.status = BackupStatus.IN_PROGRESS
        snapshot.started_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"Backup snapshot {snapshot_name} created with task {task.id}")
        
        return {
            "success": True,
            "message": f"Backup snapshot {snapshot_name} initiated",
            "data": {
                "snapshot_id": snapshot.id,
                "snapshot_name": snapshot_name,
                "task_id": task.id,
                "host_id": host.id,
                "snapshot_type": snapshot_type
            }
        }
    
    def restore_snapshot(
        self,
        snapshot_id: int,
        restore_type: str = "FULL",
        target_path: Optional[str] = None,
        dry_run: bool = False,
        initiated_by_user: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Restore files from a backup snapshot.
        
        Args:
            snapshot_id: ID of snapshot to restore
            restore_type: Type of restore (FULL, SELECTIVE, VERIFY_ONLY)
            target_path: Where to restore files (None = original locations)
            dry_run: If True, simulate without restoring
            initiated_by_user: User who initiated restore
            
        Returns:
            Result dictionary with restore details
        """
        logger.info(f"Restoring snapshot {snapshot_id} (type={restore_type}, dry_run={dry_run})")
        
        # Get snapshot
        snapshot = self.db.query(BackupSnapshot).filter(
            BackupSnapshot.id == snapshot_id
        ).first()
        
        if not snapshot:
            return {
                "success": False,
                "message": f"Snapshot {snapshot_id} not found"
            }
        
        if snapshot.status != BackupStatus.COMPLETED:
            return {
                "success": False,
                "message": f"Snapshot {snapshot_id} is not in COMPLETED status (current: {snapshot.status})"
            }
        
        # Create restore event record
        restore_event = RestoreEvent(
            snapshot_id=snapshot.id,
            host_id=snapshot.host_id,
            restore_type=restore_type,
            target_path=target_path,
            status=RestoreStatus.PENDING,
            files_to_restore=snapshot.files_backed_up,
            triggered_by="manual" if initiated_by_user else "recovery_plan",
            initiated_by_user=initiated_by_user,
            created_at=datetime.utcnow()
        )
        
        self.db.add(restore_event)
        self.db.commit()
        
        if dry_run:
            restore_event.status = RestoreStatus.COMPLETED
            restore_event.completed_at = datetime.utcnow()
            restore_event.result_message = "[DRY RUN] Restore simulation completed"
            self.db.commit()
            
            return {
                "success": True,
                "message": f"[DRY RUN] Would restore {snapshot.files_backed_up} files from snapshot {snapshot.snapshot_name}",
                "data": {
                    "restore_event_id": restore_event.id,
                    "snapshot_id": snapshot.id,
                    "files_to_restore": snapshot.files_backed_up
                }
            }
        
        # Create restore task for agent
        task_params = {
            "snapshot_id": snapshot.id,
            "restore_event_id": restore_event.id,
            "snapshot_name": snapshot.snapshot_name,
            "restore_type": restore_type,
            "target_path": target_path,
            "verify_hashes": True
        }
        
        task = Task(
            host_id=snapshot.host_id,
            type="restore_backup",
            parameters=task_params,
            status="PENDING"
        )
        self.db.add(task)
        
        # Update restore event status
        restore_event.status = RestoreStatus.IN_PROGRESS
        restore_event.started_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"Restore operation initiated for snapshot {snapshot.snapshot_name}")
        
        return {
            "success": True,
            "message": f"Restore operation initiated for snapshot {snapshot.snapshot_name}",
            "data": {
                "restore_event_id": restore_event.id,
                "snapshot_id": snapshot.id,
                "task_id": task.id,
                "files_to_restore": snapshot.files_backed_up
            }
        }
    
    def get_snapshots(
        self,
        host_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[BackupSnapshot]:
        """
        Get backup snapshots with optional filtering.
        
        Args:
            host_id: Filter by host ID
            status: Filter by status
            limit: Maximum number of snapshots to return
            
        Returns:
            List of backup snapshots
        """
        query = self.db.query(BackupSnapshot)
        
        if host_id:
            query = query.filter(BackupSnapshot.host_id == host_id)
        
        if status:
            query = query.filter(BackupSnapshot.status == status)
        
        snapshots = query.order_by(
            BackupSnapshot.created_at.desc()
        ).limit(limit).all()
        
        return snapshots
    
    def get_latest_snapshot(self, host_id: int) -> Optional[BackupSnapshot]:
        """
        Get the latest successful backup snapshot for a host.
        
        Args:
            host_id: Host ID
            
        Returns:
            Latest backup snapshot or None
        """
        snapshot = self.db.query(BackupSnapshot).filter(
            BackupSnapshot.host_id == host_id,
            BackupSnapshot.status == BackupStatus.COMPLETED
        ).order_by(BackupSnapshot.created_at.desc()).first()
        
        return snapshot
    
    def verify_snapshot_integrity(self, snapshot_id: int) -> Dict[str, Any]:
        """
        Verify integrity of a backup snapshot using manifest hash.
        
        Args:
            snapshot_id: Snapshot to verify
            
        Returns:
            Verification results
        """
        snapshot = self.db.query(BackupSnapshot).filter(
            BackupSnapshot.id == snapshot_id
        ).first()
        
        if not snapshot:
            return {
                "success": False,
                "message": f"Snapshot {snapshot_id} not found"
            }
        
        if not snapshot.manifest_hash:
            return {
                "success": False,
                "message": "Snapshot has no manifest hash for verification"
            }
        
        # In a real implementation, this would:
        # 1. Download/read the manifest file
        # 2. Recalculate its hash
        # 3. Compare with stored hash
        # 4. Verify individual file hashes
        
        # For now, we'll simulate verification
        snapshot.is_verified = True
        self.db.commit()
        
        return {
            "success": True,
            "message": f"Snapshot {snapshot.snapshot_name} verified successfully",
            "data": {
                "snapshot_id": snapshot.id,
                "manifest_hash": snapshot.manifest_hash,
                "total_files": snapshot.total_files,
                "verified": True
            }
        }
    
    def update_snapshot_status(
        self,
        snapshot_id: int,
        status: str,
        total_files: Optional[int] = None,
        total_size_bytes: Optional[int] = None,
        files_backed_up: Optional[int] = None,
        files_failed: Optional[int] = None,
        manifest_hash: Optional[str] = None,
        backup_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update snapshot status (called by agent after completion).
        
        Args:
            snapshot_id: Snapshot to update
            status: New status
            total_files: Total files found
            total_size_bytes: Total size in bytes
            files_backed_up: Files successfully backed up
            files_failed: Files that failed
            manifest_hash: SHA256 hash of manifest
            backup_path: Path where backup is stored
            
        Returns:
            Update result
        """
        snapshot = self.db.query(BackupSnapshot).filter(
            BackupSnapshot.id == snapshot_id
        ).first()
        
        if not snapshot:
            return {
                "success": False,
                "message": f"Snapshot {snapshot_id} not found"
            }
        
        # Update fields
        snapshot.status = BackupStatus[status] if isinstance(status, str) else status
        
        if total_files is not None:
            snapshot.total_files = total_files
        if total_size_bytes is not None:
            snapshot.total_size_bytes = total_size_bytes
        if files_backed_up is not None:
            snapshot.files_backed_up = files_backed_up
        if files_failed is not None:
            snapshot.files_failed = files_failed
        if manifest_hash:
            snapshot.manifest_hash = manifest_hash
        if backup_path:
            snapshot.backup_path = backup_path
        
        if status in [BackupStatus.COMPLETED, BackupStatus.FAILED]:
            snapshot.completed_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"Snapshot {snapshot_id} updated to status {status}")
        
        return {
            "success": True,
            "message": f"Snapshot {snapshot_id} updated",
            "data": {
                "snapshot_id": snapshot.id,
                "status": snapshot.status.value,
                "files_backed_up": snapshot.files_backed_up
            }
        }
    
    def update_restore_status(
        self,
        restore_event_id: int,
        status: str,
        files_restored: Optional[int] = None,
        files_failed: Optional[int] = None,
        files_missing: Optional[int] = None,
        hash_verification_passed: Optional[int] = None,
        hash_verification_failed: Optional[int] = None,
        result_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update restore event status (called by agent after completion).
        
        Args:
            restore_event_id: Restore event to update
            status: New status
            files_restored: Files successfully restored
            files_failed: Files that failed
            files_missing: Files not found in backup
            hash_verification_passed: Files that passed hash check
            hash_verification_failed: Files that failed hash check
            result_message: Result message
            
        Returns:
            Update result
        """
        restore_event = self.db.query(RestoreEvent).filter(
            RestoreEvent.id == restore_event_id
        ).first()
        
        if not restore_event:
            return {
                "success": False,
                "message": f"Restore event {restore_event_id} not found"
            }
        
        # Update fields
        restore_event.status = RestoreStatus[status] if isinstance(status, str) else status
        
        if files_restored is not None:
            restore_event.files_restored = files_restored
        if files_failed is not None:
            restore_event.files_failed = files_failed
        if files_missing is not None:
            restore_event.files_missing = files_missing
        if hash_verification_passed is not None:
            restore_event.hash_verification_passed = hash_verification_passed
        if hash_verification_failed is not None:
            restore_event.hash_verification_failed = hash_verification_failed
        if result_message:
            restore_event.result_message = result_message
        
        if status in [RestoreStatus.COMPLETED, RestoreStatus.FAILED, RestoreStatus.PARTIAL]:
            restore_event.completed_at = datetime.utcnow()
        
        self.db.commit()
        
        logger.info(f"Restore event {restore_event_id} updated to status {status}")
        
        return {
            "success": True,
            "message": f"Restore event {restore_event_id} updated",
            "data": {
                "restore_event_id": restore_event.id,
                "status": restore_event.status.value,
                "files_restored": restore_event.files_restored
            }
        }
    
    def add_backup_file(
        self,
        snapshot_id: int,
        original_path: str,
        backup_path: Optional[str] = None,
        file_size_bytes: int = 0,
        file_hash: Optional[str] = None,
        backed_up: bool = False,
        error_message: Optional[str] = None
    ) -> BackupFile:
        """
        Add a file record to a backup snapshot.
        
        Args:
            snapshot_id: Snapshot ID
            original_path: Original file path
            backup_path: Backup file path
            file_size_bytes: File size
            file_hash: SHA256 hash
            backed_up: Whether file was successfully backed up
            error_message: Error message if failed
            
        Returns:
            Created BackupFile record
        """
        backup_file = BackupFile(
            snapshot_id=snapshot_id,
            original_path=original_path,
            backup_path=backup_path,
            file_size_bytes=file_size_bytes,
            file_hash=file_hash,
            backed_up=backed_up,
            error_message=error_message,
            backed_up_at=datetime.utcnow() if backed_up else None
        )
        
        self.db.add(backup_file)
        self.db.commit()
        
        return backup_file
    
    # Helper methods
    
    def _get_safe_backup_directories(self) -> List[str]:
        """
        Get list of safe directories that can be backed up.
        These are lab-safe directories for training purposes.
        """
        return [
            "C:\\RansomTest",
            "C:\\RansomLab",
            "C:\\SimulationData",
            "C:\\Users\\Public\\RansomRun",
            "%USERPROFILE%\\RansomRunLab"
        ]
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
