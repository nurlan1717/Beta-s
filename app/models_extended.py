"""Extended models for advanced playbooks, backup/recovery, and isolation tracking."""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, Enum, JSON, Index
from sqlalchemy.orm import relationship
from .models import Base, ResponseExecutionStatus, BackupStatus, RestoreStatus


# =============================================================================
# PLAYBOOK MODELS
# =============================================================================

class Playbook(Base):
    """
    Automated response playbook.
    Maps detection rules to ordered response actions with safety controls.
    """
    __tablename__ = "playbooks"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, nullable=False, index=True)  # PB-01, PB-02, etc.
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Trigger configuration
    trigger_rule_id = Column(String(50), nullable=False, index=True)  # RR-2001, RR-2002, etc.
    severity_threshold = Column(Integer, default=0)  # Minimum alert severity to trigger
    
    # MITRE ATT&CK mapping
    mitre_techniques = Column(JSON, nullable=True)  # ["T1486", "T1490", "T1059"]
    
    # Safety and approval
    enabled = Column(Boolean, default=True, nullable=False)
    requires_approval = Column(Boolean, default=False, nullable=False)
    dry_run_only = Column(Boolean, default=False, nullable=False)
    
    # Metadata
    created_by = Column(String(100), default="system")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_triggered_at = Column(DateTime, nullable=True)
    trigger_count = Column(Integer, default=0)
    
    # Relationships
    actions = relationship("PlaybookAction", back_populates="playbook", order_by="PlaybookAction.order", cascade="all, delete-orphan")
    executions = relationship("ResponseExecution", back_populates="playbook")


class PlaybookAction(Base):
    """
    Individual action within a playbook.
    Actions are executed in order.
    """
    __tablename__ = "playbook_actions"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=False)
    order = Column(Integer, nullable=False)  # Execution order (1, 2, 3...)
    
    # Action configuration
    action_type = Column(String(100), nullable=False)  # kill_process, isolate_host, backup_snapshot, etc.
    parameters = Column(JSON, nullable=True)  # Action-specific parameters
    
    # Safety controls
    requires_approval = Column(Boolean, default=False, nullable=False)
    timeout_seconds = Column(Integer, default=300)
    
    # Conditional execution
    condition = Column(String(500), nullable=True)  # Optional condition to check before execution
    continue_on_failure = Column(Boolean, default=True, nullable=False)
    
    # Metadata
    description = Column(String(500), nullable=True)
    
    # Relationships
    playbook = relationship("Playbook", back_populates="actions")


class ResponseExecution(Base):
    """
    Tracks execution of playbook actions for idempotency and audit trail.
    """
    __tablename__ = "response_executions"
    __table_args__ = (
        Index('idx_execution_hash', 'execution_hash'),
        Index('idx_alert_playbook', 'alert_id', 'playbook_id'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    
    # What triggered this
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=False)
    playbook_action_id = Column(Integer, ForeignKey("playbook_actions.id"), nullable=True)
    
    # Execution context
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    action_type = Column(String(100), nullable=False)
    parameters = Column(JSON, nullable=True)
    
    # Status tracking
    status = Column(Enum(ResponseExecutionStatus), nullable=False)
    dry_run = Column(Boolean, default=False, nullable=False)
    
    # Approval workflow
    requires_approval = Column(Boolean, default=False, nullable=False)
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    
    # Execution results
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    result_message = Column(Text, nullable=True)
    result_data = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Idempotency tracking
    execution_hash = Column(String(64), index=True, nullable=True)  # Hash of alert_id + playbook_id + action_type
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100), default="system")
    
    # Relationships
    alert = relationship("Alert")
    playbook = relationship("Playbook", back_populates="executions")
    host = relationship("Host")
    
    __table_args__ = (
        Index('idx_execution_hash', 'execution_hash'),
        Index('idx_alert_playbook', 'alert_id', 'playbook_id'),
    )


# =============================================================================
# BACKUP & RECOVERY MODELS
# =============================================================================

class BackupSnapshot(Base):
    """
    File-level backup snapshot of a host.
    Captures files from safe directories with integrity hashing.
    """
    __tablename__ = "backup_snapshots"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    
    # Snapshot metadata
    snapshot_name = Column(String(255), nullable=False)  # e.g., "snapshot_2024-12-16_120000"
    snapshot_type = Column(String(50), default="FILE_LEVEL")  # FILE_LEVEL, VSS_SIM, FULL
    backup_path = Column(String(500), nullable=True)  # Local path or upload reference
    
    # Status
    status = Column(Enum(BackupStatus), default=BackupStatus.PENDING, nullable=False)
    
    # Statistics
    total_files = Column(Integer, default=0)
    total_size_bytes = Column(Integer, default=0)
    files_backed_up = Column(Integer, default=0)
    files_failed = Column(Integer, default=0)
    
    # Integrity
    manifest_hash = Column(String(64), nullable=True)  # SHA256 of manifest file
    is_verified = Column(Boolean, default=False)
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Trigger context
    triggered_by = Column(String(100), nullable=True)  # "playbook", "manual", "scheduled"
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    
    # Upload tracking
    uploaded = Column(Boolean, default=False)
    upload_path = Column(String(500), nullable=True)
    
    # Relationships
    host = relationship("Host", back_populates="backup_snapshots")
    files = relationship("BackupFile", back_populates="snapshot", cascade="all, delete-orphan")
    restore_events = relationship("RestoreEvent", back_populates="snapshot")


class BackupFile(Base):
    """
    Individual file within a backup snapshot.
    """
    __tablename__ = "backup_files"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("backup_snapshots.id"), nullable=False, index=True)
    
    # File information
    original_path = Column(String(1000), nullable=False)
    backup_path = Column(String(1000), nullable=True)
    file_size_bytes = Column(Integer, default=0)
    file_hash = Column(String(64), nullable=True)  # SHA256
    
    # Status
    backed_up = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    original_modified_at = Column(DateTime, nullable=True)
    backed_up_at = Column(DateTime, nullable=True)
    
    # Relationships
    snapshot = relationship("BackupSnapshot", back_populates="files")


class RestoreEvent(Base):
    """
    Tracks restore operations from backup snapshots.
    """
    __tablename__ = "restore_events"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("backup_snapshots.id"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    
    # Restore configuration
    restore_type = Column(String(50), default="FULL")  # FULL, SELECTIVE, VERIFY_ONLY
    target_path = Column(String(500), nullable=True)  # Where to restore files
    
    # Status
    status = Column(Enum(RestoreStatus), default=RestoreStatus.PENDING, nullable=False)
    
    # Statistics
    files_to_restore = Column(Integer, default=0)
    files_restored = Column(Integer, default=0)
    files_failed = Column(Integer, default=0)
    files_missing = Column(Integer, default=0)
    
    # Integrity verification
    hash_verification_passed = Column(Integer, default=0)
    hash_verification_failed = Column(Integer, default=0)
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Trigger context
    triggered_by = Column(String(100), nullable=True)  # "recovery_plan", "manual"
    initiated_by_user = Column(String(100), nullable=True)
    
    # Results
    result_message = Column(Text, nullable=True)
    result_data = Column(JSON, nullable=True)
    
    # Relationships
    snapshot = relationship("BackupSnapshot", back_populates="restore_events")
    host = relationship("Host")


# =============================================================================
# ISOLATION TRACKING MODELS
# =============================================================================

class IsolationEvent(Base):
    """
    Tracks host isolation/de-isolation events for audit trail.
    """
    __tablename__ = "isolation_events"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    
    # Event type
    event_type = Column(String(50), nullable=False)  # ISOLATE, DEISOLATE, TTL_EXPIRE, POLICY_CHANGE
    
    # Isolation configuration
    isolation_policy = Column(String(50), nullable=True)  # Policy applied
    ttl_minutes = Column(Integer, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    
    # Context
    triggered_by = Column(String(100), nullable=True)  # "playbook", "manual", "ttl_expiry"
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=True)
    initiated_by_user = Column(String(100), nullable=True)
    
    # Execution
    dry_run = Column(Boolean, default=False)
    success = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    
    # Firewall rules applied (for escape hatch)
    firewall_rules_applied = Column(JSON, nullable=True)  # List of rule names/IDs created
    
    # Timing
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    host = relationship("Host", back_populates="isolation_events")


# =============================================================================
# SYSTEM CONFIGURATION
# =============================================================================

class SystemConfig(Base):
    """
    Global system configuration for response automation.
    """
    __tablename__ = "system_config"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(String(1000), nullable=True)
    value_type = Column(String(50), default="string")  # string, boolean, integer, json
    description = Column(Text, nullable=True)
    
    # Metadata
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(100), nullable=True)


