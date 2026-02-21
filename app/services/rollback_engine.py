"""
AutoRollback Engine - Safe file-level rollback from backup snapshots.

SAFETY CONSTRAINTS:
- Only operates on configured safe paths (lab directories)
- Default blocked: C:\Windows, C:\Program Files*, AppData, system profiles
- Supports dry_run mode (simulate without changes)
- Requires approval by default for destructive operations
- Full audit trail with before/after hashes

Features:
- Build rollback plan from snapshot
- Execute plan via agent tasks
- Verify restored file hashes
- Handle conflicts (quarantine/overwrite/skip)
- Cleanup ransomware extensions (.locked, .encrypted, etc.)
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_

from ..models import (
    Host, Task, BackupSnapshot, BackupFile, 
    RollbackPlan, RollbackFileAction, RollbackReport,
    RollbackPlanStatus, RollbackActionType, BackupStatus,
    RunEvent, EventType
)

logger = logging.getLogger(__name__)


# Default safe paths for lab environment
DEFAULT_SAFE_PATHS = [
    r"C:\RansomTest",
    r"C:\RansomLab",
    r"C:\Users\Public\Documents",
]

# Paths that are ALWAYS blocked (system directories)
BLOCKED_PATHS = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
]

# User profile paths that require explicit allow-listing
SENSITIVE_USER_PATHS = [
    "AppData",
    "Application Data",
    "Local Settings",
    "NTUSER.DAT",
]

# Common ransomware extensions to clean up
DEFAULT_CLEANUP_EXTENSIONS = [
    ".locked",
    ".encrypted",
    ".dwcrypt",
    ".enc",
    ".crypted",
    ".crypt",
]


class RollbackEngine:
    """
    AutoRollback engine for safe file restoration from backups.
    
    Key safety features:
    - Path validation against safe paths allow-list
    - Blocked paths enforcement
    - Dry-run mode
    - Approval workflow
    - Full audit logging
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def _is_path_safe(self, path: str, safe_paths: List[str]) -> Tuple[bool, str]:
        """
        Check if a path is safe to operate on.
        
        Returns:
            (is_safe, reason)
        """
        if not path:
            return False, "Empty path"
        
        # Normalize path
        norm_path = os.path.normpath(path).lower()
        
        # Check blocked paths first
        for blocked in BLOCKED_PATHS:
            if norm_path.startswith(blocked.lower()):
                return False, f"Path is in blocked system directory: {blocked}"
        
        # Check sensitive user paths
        for sensitive in SENSITIVE_USER_PATHS:
            if sensitive.lower() in norm_path:
                # Only allow if explicitly in safe_paths
                explicitly_allowed = any(
                    sensitive.lower() in sp.lower() 
                    for sp in safe_paths
                )
                if not explicitly_allowed:
                    return False, f"Path contains sensitive user directory: {sensitive}"
        
        # Check if path is under a safe path
        for safe_path in safe_paths:
            safe_norm = os.path.normpath(safe_path).lower()
            if norm_path.startswith(safe_norm):
                return True, "Path is under allowed safe path"
        
        return False, "Path is not under any configured safe path"
    
    def _get_safe_paths(self, custom_paths: Optional[List[str]] = None) -> List[str]:
        """Get the effective safe paths list."""
        if custom_paths:
            # Merge custom with defaults, validate each
            paths = list(set(DEFAULT_SAFE_PATHS + custom_paths))
        else:
            paths = DEFAULT_SAFE_PATHS.copy()
        
        # Filter out any blocked paths
        valid_paths = []
        for path in paths:
            is_blocked = any(
                os.path.normpath(path).lower().startswith(
                    os.path.normpath(blocked).lower()
                )
                for blocked in BLOCKED_PATHS
            )
            if not is_blocked:
                valid_paths.append(path)
            else:
                logger.warning(f"Removed blocked path from safe_paths: {path}")
        
        return valid_paths
    
    def get_latest_snapshot(self, host_id: int) -> Optional[BackupSnapshot]:
        """Get the most recent completed backup snapshot for a host."""
        return self.db.query(BackupSnapshot).filter(
            BackupSnapshot.host_id == host_id,
            BackupSnapshot.status == BackupStatus.COMPLETED
        ).order_by(BackupSnapshot.created_at.desc()).first()
    
    def _create_emergency_snapshot(self, host: Host, safe_paths: List[str]) -> Optional[BackupSnapshot]:
        """
        Create an emergency backup snapshot for rollback when none exists.
        ACTUALLY COPIES files to a backup directory for real rollback support.
        """
        from datetime import datetime
        import hashlib
        import shutil
        
        logger.info(f"Creating emergency snapshot for host {host.name}")
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        snapshot_name = f"emergency_snapshot_{host.agent_id}_{timestamp}"
        
        # Create backup directory
        backup_base_dir = rf"C:\RansomRun\backups\{snapshot_name}"
        os.makedirs(backup_base_dir, exist_ok=True)
        
        # Create snapshot record
        snapshot = BackupSnapshot(
            host_id=host.id,
            snapshot_name=snapshot_name,
            snapshot_type="EMERGENCY",
            backup_path=backup_base_dir,
            status=BackupStatus.COMPLETED,
            triggered_by="autorollback_emergency",
            created_at=datetime.utcnow(),
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            total_files=0,
            files_backed_up=0,
            files_failed=0
        )
        
        self.db.add(snapshot)
        self.db.flush()
        
        # Scan safe paths and create actual backup copies
        files_found = 0
        files_failed = 0
        for safe_path in safe_paths:
            if not os.path.exists(safe_path):
                continue
            
            for root, dirs, files in os.walk(safe_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Skip hidden/system files
                    if filename.startswith('.'):
                        continue
                    
                    try:
                        # Compute file hash
                        file_hash = None
                        file_size = os.path.getsize(filepath)
                        
                        if file_size < 10 * 1024 * 1024:  # Only hash files < 10MB
                            sha256 = hashlib.sha256()
                            with open(filepath, 'rb') as f:
                                for chunk in iter(lambda: f.read(8192), b''):
                                    sha256.update(chunk)
                            file_hash = sha256.hexdigest()
                        
                        # Create backup path preserving directory structure
                        rel_path = os.path.relpath(filepath, os.path.splitdrive(filepath)[0] + os.sep)
                        backup_path = os.path.join(backup_base_dir, rel_path)
                        
                        # Create backup directory structure and copy file
                        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                        shutil.copy2(filepath, backup_path)
                        
                        # Create backup file record with ACTUAL backup path
                        from ..models import BackupFile
                        backup_file = BackupFile(
                            snapshot_id=snapshot.id,
                            original_path=filepath,
                            backup_path=backup_path,  # Actual backup location
                            file_size_bytes=file_size,
                            file_hash=file_hash,
                            backed_up=True,
                            backed_up_at=datetime.utcnow()
                        )
                        self.db.add(backup_file)
                        files_found += 1
                        logger.debug(f"Backed up: {filepath} -> {backup_path}")
                        
                    except Exception as e:
                        logger.warning(f"Failed to backup file {filepath}: {e}")
                        files_failed += 1
        
        # Update snapshot stats
        snapshot.total_files = files_found + files_failed
        snapshot.files_backed_up = files_found
        snapshot.files_failed = files_failed
        snapshot.manifest_hash = hashlib.sha256(f"{snapshot_name}:{files_found}".encode()).hexdigest()
        
        self.db.commit()
        
        logger.info(f"Emergency snapshot created: {snapshot_name} ({files_found} files backed up to {backup_base_dir})")
        
        return snapshot
    
    def create_plan(
        self,
        host_id: int,
        run_id: Optional[int] = None,
        snapshot_id: Optional[int] = None,
        safe_paths: Optional[List[str]] = None,
        conflict_policy: str = "QUARANTINE",
        cleanup_extensions: Optional[List[str]] = None,
        dry_run: bool = False,
        require_approval: bool = True,
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """
        Create a rollback plan for a host.
        
        Args:
            host_id: Target host ID
            run_id: Optional linked simulation run ID
            snapshot_id: Snapshot to restore from (auto-selects latest if None)
            safe_paths: Custom safe paths to allow
            conflict_policy: QUARANTINE, OVERWRITE, or SKIP
            cleanup_extensions: Extensions to clean up (remove)
            dry_run: If True, plan is for dry-run only
            require_approval: If True, requires manual approval to execute
            created_by: User who created the plan
            
        Returns:
            Result dictionary with plan details
        """
        logger.info(f"Creating rollback plan for host {host_id} (dry_run={dry_run})")
        
        # Validate host exists
        host = self.db.query(Host).filter(Host.id == host_id).first()
        if not host:
            return {"success": False, "error": "Host not found"}
        
        # Check for existing active plan on this host
        active_plan = self.db.query(RollbackPlan).filter(
            RollbackPlan.host_id == host_id,
            RollbackPlan.status.in_([
                RollbackPlanStatus.PENDING_APPROVAL,
                RollbackPlanStatus.APPROVED,
                RollbackPlanStatus.EXECUTING
            ])
        ).first()
        
        if active_plan:
            return {
                "success": False, 
                "error": f"Active rollback plan already exists for this host (plan_id: {active_plan.id})"
            }
        
        # Get snapshot
        if snapshot_id:
            snapshot = self.db.query(BackupSnapshot).filter(
                BackupSnapshot.id == snapshot_id,
                BackupSnapshot.host_id == host_id
            ).first()
            if not snapshot:
                return {"success": False, "error": "Snapshot not found or doesn't belong to host"}
        else:
            snapshot = self.get_latest_snapshot(host_id)
            if not snapshot:
                # Auto-create an emergency snapshot if none exists
                logger.info(f"No snapshot found for host {host_id}, creating emergency snapshot...")
                snapshot = self._create_emergency_snapshot(host, effective_safe_paths if 'effective_safe_paths' in dir() else self._get_safe_paths(safe_paths))
                if not snapshot:
                    return {
                        "success": False, 
                        "error": "No backup snapshot found and failed to create emergency snapshot",
                        "suggestion": "Create a backup snapshot manually via /api/backup/snapshot/{host_id}"
                    }
        
        # Get effective safe paths
        effective_safe_paths = self._get_safe_paths(safe_paths)
        
        # Get cleanup extensions
        effective_cleanup_ext = cleanup_extensions or DEFAULT_CLEANUP_EXTENSIONS
        
        # Create plan
        plan = RollbackPlan(
            host_id=host_id,
            run_id=run_id,
            snapshot_id=snapshot.id,
            status=RollbackPlanStatus.DRAFT,
            dry_run=dry_run,
            safe_paths=effective_safe_paths,
            conflict_policy=conflict_policy,
            cleanup_extensions=effective_cleanup_ext,
            requires_approval=require_approval,
            created_by=created_by,
            created_at=datetime.utcnow(),
            config_json={
                "snapshot_name": snapshot.snapshot_name,
                "snapshot_type": snapshot.snapshot_type,
                "host_name": host.name
            }
        )
        
        self.db.add(plan)
        self.db.flush()  # Get plan ID
        
        # Build file actions from snapshot
        files_to_restore = 0
        files_to_skip = 0
        files_with_conflicts = 0
        
        for backup_file in snapshot.files:
            if not backup_file.backed_up:
                continue
            
            # Check if path is safe
            is_safe, reason = self._is_path_safe(
                backup_file.original_path, 
                effective_safe_paths
            )
            
            if not is_safe:
                # Skip unsafe paths
                action = RollbackFileAction(
                    plan_id=plan.id,
                    original_path=backup_file.original_path,
                    backup_path=backup_file.backup_path,
                    action_type=RollbackActionType.SKIP,
                    action_reason=f"Path not safe: {reason}",
                    expected_hash=backup_file.file_hash
                )
                files_to_skip += 1
            else:
                # Plan to restore this file
                action = RollbackFileAction(
                    plan_id=plan.id,
                    original_path=backup_file.original_path,
                    backup_path=backup_file.backup_path,
                    action_type=RollbackActionType.RESTORE,
                    action_reason="File in safe path, will restore from backup",
                    expected_hash=backup_file.file_hash
                )
                files_to_restore += 1
            
            self.db.add(action)
        
        # Update plan summary
        plan.total_files = files_to_restore + files_to_skip
        plan.files_to_restore = files_to_restore
        plan.files_to_skip = files_to_skip
        plan.files_with_conflicts = files_with_conflicts
        
        # Set status based on approval requirement
        if require_approval:
            plan.status = RollbackPlanStatus.PENDING_APPROVAL
        else:
            plan.status = RollbackPlanStatus.APPROVED
        
        # Create timeline event for plan creation
        if run_id:
            event = RunEvent(
                run_id=run_id,
                host_id=host_id,
                event_type=EventType.ROLLBACK_PLANNED,
                timestamp=datetime.utcnow(),
                details={
                    "plan_id": plan.id,
                    "snapshot_id": snapshot.id,
                    "files_to_restore": files_to_restore,
                    "files_to_skip": files_to_skip,
                    "dry_run": dry_run,
                    "requires_approval": require_approval
                }
            )
            self.db.add(event)
        
        self.db.commit()
        
        logger.info(f"Created rollback plan {plan.id}: {files_to_restore} files to restore, {files_to_skip} skipped")
        
        return {
            "success": True,
            "message": f"Rollback plan created successfully",
            "data": {
                "plan_id": plan.id,
                "host_id": host_id,
                "host_name": host.name,
                "snapshot_id": snapshot.id,
                "snapshot_name": snapshot.snapshot_name,
                "status": plan.status.value,
                "dry_run": dry_run,
                "requires_approval": require_approval,
                "safe_paths": effective_safe_paths,
                "summary": {
                    "total_files": plan.total_files,
                    "files_to_restore": files_to_restore,
                    "files_to_skip": files_to_skip,
                    "files_with_conflicts": files_with_conflicts
                }
            }
        }
    
    def approve_plan(
        self, 
        plan_id: int, 
        approved_by: str
    ) -> Dict[str, Any]:
        """Approve a rollback plan for execution."""
        plan = self.db.query(RollbackPlan).filter(
            RollbackPlan.id == plan_id
        ).first()
        
        if not plan:
            return {"success": False, "error": "Plan not found"}
        
        if plan.status != RollbackPlanStatus.PENDING_APPROVAL:
            return {
                "success": False, 
                "error": f"Plan cannot be approved in current status: {plan.status.value}"
            }
        
        plan.status = RollbackPlanStatus.APPROVED
        plan.approved_by = approved_by
        plan.approved_at = datetime.utcnow()
        
        # Create timeline event for approval
        if plan.run_id:
            event = RunEvent(
                run_id=plan.run_id,
                host_id=plan.host_id,
                event_type=EventType.ROLLBACK_APPROVED,
                timestamp=datetime.utcnow(),
                details={
                    "plan_id": plan_id,
                    "approved_by": approved_by
                }
            )
            self.db.add(event)
        
        self.db.commit()
        
        logger.info(f"Rollback plan {plan_id} approved by {approved_by}")
        
        return {
            "success": True,
            "message": "Plan approved successfully",
            "data": {
                "plan_id": plan_id,
                "status": plan.status.value,
                "approved_by": approved_by,
                "approved_at": plan.approved_at.isoformat()
            }
        }
    
    def execute_plan(
        self, 
        plan_id: int,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Execute a rollback plan by creating agent tasks.
        
        Args:
            plan_id: Plan to execute
            force: Force execution even if already executed
            
        Returns:
            Result dictionary with execution details
        """
        plan = self.db.query(RollbackPlan).filter(
            RollbackPlan.id == plan_id
        ).first()
        
        if not plan:
            return {"success": False, "error": "Plan not found"}
        
        # Check status
        if plan.status == RollbackPlanStatus.EXECUTING:
            return {"success": False, "error": "Plan is already executing"}
        
        if plan.status == RollbackPlanStatus.COMPLETED and not force:
            return {"success": False, "error": "Plan already completed. Use force=true to re-execute"}
        
        if plan.status not in [RollbackPlanStatus.APPROVED, RollbackPlanStatus.COMPLETED]:
            return {
                "success": False, 
                "error": f"Plan must be approved before execution. Current status: {plan.status.value}"
            }
        
        # Acquire execution lock
        lock_token = secrets.token_hex(32)
        try:
            plan.execution_lock = lock_token
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            return {"success": False, "error": "Failed to acquire execution lock - parallel execution in progress"}
        
        # Update status
        plan.status = RollbackPlanStatus.EXECUTING
        plan.started_at = datetime.utcnow()
        
        # Create timeline event for execution start
        if plan.run_id:
            event = RunEvent(
                run_id=plan.run_id,
                host_id=plan.host_id,
                event_type=EventType.ROLLBACK_STARTED,
                timestamp=datetime.utcnow(),
                details={
                    "plan_id": plan.id,
                    "dry_run": plan.dry_run,
                    "files_to_restore": plan.files_to_restore
                }
            )
            self.db.add(event)
        
        self.db.commit()
        
        # Build task parameters
        restore_actions = []
        for action in plan.file_actions:
            if action.action_type == RollbackActionType.RESTORE:
                restore_actions.append({
                    "action_id": action.id,
                    "original_path": action.original_path,
                    "backup_path": action.backup_path,
                    "expected_hash": action.expected_hash,
                    "action_type": action.action_type.value
                })
        
        task_params = {
            "plan_id": plan.id,
            "dry_run": plan.dry_run,
            "safe_paths": plan.safe_paths,
            "conflict_policy": plan.conflict_policy,
            "cleanup_extensions": plan.cleanup_extensions,
            "restore_actions": restore_actions,
            "conflict_directory": f"C:\\RansomRun\\rollback_conflicts\\{plan.id}"
        }
        
        # Create agent task
        task = Task(
            host_id=plan.host_id,
            type="rollback_restore_from_snapshot",
            parameters=task_params,
            status="PENDING"
        )
        self.db.add(task)
        self.db.commit()
        
        logger.info(f"Executing rollback plan {plan_id} via task {task.id}")
        
        return {
            "success": True,
            "message": f"Rollback execution started",
            "data": {
                "plan_id": plan_id,
                "task_id": task.id,
                "status": plan.status.value,
                "dry_run": plan.dry_run,
                "files_to_restore": len(restore_actions)
            }
        }
    
    def process_execution_result(
        self,
        plan_id: int,
        result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process the result from agent rollback execution.
        
        Args:
            plan_id: Plan that was executed
            result: Result dictionary from agent
            
        Returns:
            Result dictionary with report details
        """
        plan = self.db.query(RollbackPlan).filter(
            RollbackPlan.id == plan_id
        ).first()
        
        if not plan:
            return {"success": False, "error": "Plan not found"}
        
        # Update file actions based on result
        file_results = result.get("file_results", [])
        
        files_restored = 0
        files_skipped = 0
        files_conflict_moved = 0
        files_cleaned = 0
        files_failed = 0
        hash_passed = 0
        hash_failed = 0
        errors = []
        
        for fr in file_results:
            action_id = fr.get("action_id")
            if action_id:
                action = self.db.query(RollbackFileAction).filter(
                    RollbackFileAction.id == action_id
                ).first()
                
                if action:
                    action.executed = True
                    action.executed_at = datetime.utcnow()
                    action.success = fr.get("success", False)
                    action.before_hash = fr.get("before_hash")
                    action.after_hash = fr.get("after_hash")
                    action.hash_verified = fr.get("hash_verified")
                    action.error_message = fr.get("error")
                    action.conflict_backup_path = fr.get("conflict_backup_path")
                    
                    if action.success:
                        if action.action_type == RollbackActionType.RESTORE:
                            files_restored += 1
                        elif action.action_type == RollbackActionType.CONFLICT_MOVE:
                            files_conflict_moved += 1
                        elif action.action_type == RollbackActionType.CLEANUP_EXTENSION:
                            files_cleaned += 1
                        
                        if action.hash_verified:
                            hash_passed += 1
                        elif action.hash_verified is False:
                            hash_failed += 1
                    else:
                        files_failed += 1
                        if action.error_message:
                            errors.append(f"{action.original_path}: {action.error_message}")
        
        # Determine final status
        if files_failed == 0 and hash_failed == 0:
            final_status = "SUCCESS"
            plan.status = RollbackPlanStatus.COMPLETED
        elif files_restored > 0:
            final_status = "PARTIAL"
            plan.status = RollbackPlanStatus.PARTIAL
        else:
            final_status = "FAILED"
            plan.status = RollbackPlanStatus.FAILED
        
        # Calculate elapsed time
        elapsed = 0.0
        if plan.started_at:
            elapsed = (datetime.utcnow() - plan.started_at).total_seconds()
        
        plan.completed_at = datetime.utcnow()
        plan.execution_lock = None
        
        # Create report
        report = RollbackReport(
            plan_id=plan.id,
            files_restored=files_restored,
            files_skipped=files_skipped,
            files_conflict_moved=files_conflict_moved,
            files_cleaned_extensions=files_cleaned,
            files_failed=files_failed,
            hash_verifications_passed=hash_passed,
            hash_verifications_failed=hash_failed,
            elapsed_seconds=elapsed,
            final_status=final_status,
            summary_json={
                "total_processed": len(file_results),
                "dry_run": plan.dry_run,
                "snapshot_id": plan.snapshot_id,
                "safe_paths": plan.safe_paths
            },
            errors=errors if errors else None
        )
        
        self.db.add(report)
        self.db.commit()
        
        logger.info(f"Rollback plan {plan_id} completed: {final_status}")
        
        return {
            "success": True,
            "data": {
                "plan_id": plan_id,
                "report_id": report.id,
                "final_status": final_status,
                "summary": {
                    "files_restored": files_restored,
                    "files_failed": files_failed,
                    "hash_verifications_passed": hash_passed,
                    "hash_verifications_failed": hash_failed,
                    "elapsed_seconds": elapsed
                },
                "errors": errors if errors else None
            }
        }
    
    def get_plan(self, plan_id: int) -> Optional[Dict[str, Any]]:
        """Get detailed plan information."""
        plan = self.db.query(RollbackPlan).filter(
            RollbackPlan.id == plan_id
        ).first()
        
        if not plan:
            return None
        
        return {
            "id": plan.id,
            "host_id": plan.host_id,
            "host_name": plan.host.name if plan.host else None,
            "run_id": plan.run_id,
            "snapshot_id": plan.snapshot_id,
            "snapshot_name": plan.snapshot.snapshot_name if plan.snapshot else None,
            "status": plan.status.value,
            "dry_run": plan.dry_run,
            "safe_paths": plan.safe_paths,
            "conflict_policy": plan.conflict_policy,
            "cleanup_extensions": plan.cleanup_extensions,
            "requires_approval": plan.requires_approval,
            "approved_by": plan.approved_by,
            "approved_at": plan.approved_at.isoformat() if plan.approved_at else None,
            "created_at": plan.created_at.isoformat(),
            "created_by": plan.created_by,
            "started_at": plan.started_at.isoformat() if plan.started_at else None,
            "completed_at": plan.completed_at.isoformat() if plan.completed_at else None,
            "summary": {
                "total_files": plan.total_files,
                "files_to_restore": plan.files_to_restore,
                "files_to_skip": plan.files_to_skip,
                "files_with_conflicts": plan.files_with_conflicts
            },
            "file_actions": [
                {
                    "id": a.id,
                    "original_path": a.original_path,
                    "action_type": a.action_type.value,
                    "action_reason": a.action_reason,
                    "executed": a.executed,
                    "success": a.success,
                    "hash_verified": a.hash_verified,
                    "error_message": a.error_message
                }
                for a in plan.file_actions[:100]  # Limit to first 100
            ],
            "report": self._get_report_dict(plan.report) if plan.report else None
        }
    
    def _get_report_dict(self, report: RollbackReport) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "id": report.id,
            "files_restored": report.files_restored,
            "files_skipped": report.files_skipped,
            "files_conflict_moved": report.files_conflict_moved,
            "files_cleaned_extensions": report.files_cleaned_extensions,
            "files_failed": report.files_failed,
            "hash_verifications_passed": report.hash_verifications_passed,
            "hash_verifications_failed": report.hash_verifications_failed,
            "elapsed_seconds": report.elapsed_seconds,
            "final_status": report.final_status,
            "summary_json": report.summary_json,
            "errors": report.errors,
            "created_at": report.created_at.isoformat()
        }
    
    def list_plans(
        self, 
        host_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List rollback plans with optional filters."""
        query = self.db.query(RollbackPlan)
        
        if host_id:
            query = query.filter(RollbackPlan.host_id == host_id)
        
        if status:
            try:
                status_enum = RollbackPlanStatus(status)
                query = query.filter(RollbackPlan.status == status_enum)
            except ValueError:
                pass
        
        plans = query.order_by(RollbackPlan.created_at.desc()).limit(limit).all()
        
        return [
            {
                "id": p.id,
                "host_id": p.host_id,
                "host_name": p.host.name if p.host else None,
                "snapshot_id": p.snapshot_id,
                "status": p.status.value,
                "dry_run": p.dry_run,
                "files_to_restore": p.files_to_restore,
                "requires_approval": p.requires_approval,
                "approved_by": p.approved_by,
                "created_at": p.created_at.isoformat(),
                "completed_at": p.completed_at.isoformat() if p.completed_at else None,
                "final_status": p.report.final_status if p.report else None
            }
            for p in plans
        ]
    
    def get_report(self, plan_id: int) -> Optional[Dict[str, Any]]:
        """Get the report for a rollback plan."""
        report = self.db.query(RollbackReport).filter(
            RollbackReport.plan_id == plan_id
        ).first()
        
        if not report:
            return None
        
        return self._get_report_dict(report)
    
    def cancel_plan(self, plan_id: int, canceled_by: str) -> Dict[str, Any]:
        """Cancel a pending rollback plan."""
        plan = self.db.query(RollbackPlan).filter(
            RollbackPlan.id == plan_id
        ).first()
        
        if not plan:
            return {"success": False, "error": "Plan not found"}
        
        if plan.status in [RollbackPlanStatus.EXECUTING, RollbackPlanStatus.COMPLETED]:
            return {"success": False, "error": f"Cannot cancel plan in status: {plan.status.value}"}
        
        plan.status = RollbackPlanStatus.CANCELED
        plan.config_json = plan.config_json or {}
        plan.config_json["canceled_by"] = canceled_by
        plan.config_json["canceled_at"] = datetime.utcnow().isoformat()
        
        self.db.commit()
        
        return {"success": True, "message": "Plan canceled"}
    
    def check_host_autorollback_enabled(self, host_id: int) -> Tuple[bool, str]:
        """
        Check if autorollback is enabled for a host.
        
        Returns:
            (enabled, reason)
        """
        host = self.db.query(Host).filter(Host.id == host_id).first()
        if not host:
            return False, "Host not found"
        
        # Check host-level setting (stored in config or as column)
        # For now, check if host allows auto-response as proxy
        if not host.allow_auto_response:
            return False, "Host does not allow auto-response"
        
        # Check global setting
        from ..models import SystemConfig
        global_config = self.db.query(SystemConfig).filter(
            SystemConfig.key == "autorollback_enabled"
        ).first()
        
        if global_config and global_config.value.lower() != "true":
            return False, "Global autorollback is disabled"
        
        return True, "AutoRollback is enabled for this host"
