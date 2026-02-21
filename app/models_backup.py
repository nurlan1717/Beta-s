"""SQLAlchemy models for Backup & Restore feature.

LAB-SAFE backup and recovery system for RansomRun platform.
Supports file-level snapshots with integrity verification.
"""

import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float,
    ForeignKey, Enum, JSON, Index
)
from sqlalchemy.orm import relationship

from .models import Base


# =============================================================================
# ENUMS
# =============================================================================

class BackupScopeType(str, enum.Enum):
    """Type of backup scope."""
    FOLDER = "folder"           # Specific folder paths
    PROFILE = "profile"         # Preset profile (e.g., "Important Server Data")


class BackupScheduleType(str, enum.Enum):
    """When backups should run."""
    MANUAL = "manual"                   # Only on-demand
    PRE_SIMULATION = "pre_simulation"   # Before each simulation run
    INTERVAL = "interval"               # Regular intervals


class BackupJobType(str, enum.Enum):
    """Type of backup job."""
    BACKUP = "backup"
    RESTORE = "restore"


class BackupJobStatus(str, enum.Enum):
    """Status of a backup/restore job."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


class BackupIntegrityStatus(str, enum.Enum):
    """Integrity check status for snapshots."""
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    UNCHECKED = "unchecked"


class RestoreMode(str, enum.Enum):
    """How to restore files."""
    IN_PLACE = "in_place"               # Restore to original location
    RESTORE_TO_NEW_FOLDER = "restore_to_new_folder"  # Restore to alternate location


# =============================================================================
# BACKUP PLAN MODEL
# =============================================================================

class BackupPlan(Base):
    """
    Defines what to protect and how often.
    
    A plan specifies:
    - Which paths to backup
    - Include/exclude patterns
    - Schedule (manual, pre-simulation, interval)
    - Retention policy
    """
    __tablename__ = "backup_plans"
    __table_args__ = (
        Index('idx_backup_plan_enabled', 'enabled'),
        Index('idx_backup_plan_schedule', 'schedule_type'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    
    # Scope configuration
    scope_type = Column(Enum(BackupScopeType), default=BackupScopeType.FOLDER, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    
    # Paths to backup (JSON array)
    # Example: ["C:\\RansomTest\\target_data", "C:\\RansomTest\\important"]
    paths_json = Column(JSON, nullable=False, default=list)
    
    # Glob patterns for filtering (optional)
    # Example include: ["*.docx", "*.xlsx", "*.pdf"]
    # Example exclude: ["*.tmp", "*.log", "Thumbs.db"]
    include_globs = Column(JSON, nullable=True)
    exclude_globs = Column(JSON, nullable=True)
    
    # Schedule configuration
    schedule_type = Column(Enum(BackupScheduleType), default=BackupScheduleType.MANUAL, nullable=False)
    interval_minutes = Column(Integer, nullable=True)  # For interval schedule
    
    # Retention policy
    retention_count = Column(Integer, default=5, nullable=False)
    
    # Storage configuration
    # If null, uses default: C:\ProgramData\RansomRun\backups\
    storage_base_path = Column(String(500), nullable=True)
    
    # Network share option (optional)
    # Example: \\BACKUP-SERVER\RansomRunBackups
    network_share_path = Column(String(500), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=True)
    
    # Relationships
    jobs = relationship("BackupJob", back_populates="plan")
    # Note: snapshots relationship removed - BackupSnapshot in models.py has different structure
    created_by = relationship("AuthUser")


# =============================================================================
# BACKUP JOB MODEL
# =============================================================================

class BackupJob(Base):
    """
    Tracks individual backup or restore operations.
    
    Each job represents a single execution of a backup plan
    or a restore operation from a snapshot.
    """
    __tablename__ = "backup_jobs"
    __table_args__ = (
        Index('idx_backup_job_host', 'host_id'),
        Index('idx_backup_job_status', 'status'),
        Index('idx_backup_job_type', 'job_type'),
        Index('idx_backup_job_run', 'run_id'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    
    # References
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("backup_plans.id"), nullable=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("backup_snapshots.id"), nullable=True)  # For restore jobs
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=True)  # Agent task
    
    # Job configuration
    job_type = Column(Enum(BackupJobType), nullable=False)
    status = Column(Enum(BackupJobStatus), default=BackupJobStatus.PENDING, nullable=False)
    dry_run = Column(Boolean, default=False, nullable=False)
    
    # For restore jobs
    restore_mode = Column(Enum(RestoreMode), nullable=True)
    target_override_path = Column(String(500), nullable=True)  # For restore_to_new_folder
    
    # Execution timing
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    
    # User who triggered
    requested_by_user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=True)
    
    # Detailed results (JSON)
    details_json = Column(JSON, nullable=True)
    # Structure for backup:
    # {
    #   "paths_processed": [...],
    #   "file_count": 123,
    #   "total_bytes": 456789,
    #   "errors": [],
    #   "snapshot_path": "..."
    # }
    # Structure for restore:
    # {
    #   "source_snapshot": "...",
    #   "restored_paths": [...],
    #   "files_restored": 100,
    #   "files_failed": 0,
    #   "verification_passed": true
    # }
    
    # Command output
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    host = relationship("Host")
    plan = relationship("BackupPlan", back_populates="jobs")
    run = relationship("Run")
    # Note: snapshot relationship uses legacy BackupSnapshot from models.py
    task = relationship("Task")
    requested_by = relationship("AuthUser")


# =============================================================================
# NOTE: BackupSnapshot class is defined in models.py (legacy)
# Use that class for snapshot operations. This file only defines BackupPlan
# and BackupJob which are new additions.
# =============================================================================
