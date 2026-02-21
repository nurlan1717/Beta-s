"""
Backup, Recovery, and Isolation models to be appended to models.py
These models are defined here and will be imported in models.py
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship


# These will be added to models.py - using string references for now
BACKUP_ISOLATION_MODELS = """

# =============================================================================
# BACKUP & RECOVERY MODELS
# =============================================================================

class BackupSnapshot(Base):
    __tablename__ = "backup_snapshots"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    
    snapshot_name = Column(String(255), nullable=False)
    snapshot_type = Column(String(50), default="FILE_LEVEL")
    backup_path = Column(String(500), nullable=True)
    
    status = Column(Enum(BackupStatus), default=BackupStatus.PENDING, nullable=False)
    
    total_files = Column(Integer, default=0)
    total_size_bytes = Column(Integer, default=0)
    files_backed_up = Column(Integer, default=0)
    files_failed = Column(Integer, default=0)
    
    manifest_hash = Column(String(64), nullable=True)
    is_verified = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    triggered_by = Column(String(100), nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    
    uploaded = Column(Boolean, default=False)
    upload_path = Column(String(500), nullable=True)
    
    host = relationship("Host", back_populates="backup_snapshots")
    files = relationship("BackupFile", back_populates="snapshot", cascade="all, delete-orphan")
    restore_events = relationship("RestoreEvent", back_populates="snapshot")


class BackupFile(Base):
    __tablename__ = "backup_files"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("backup_snapshots.id"), nullable=False, index=True)
    
    original_path = Column(String(1000), nullable=False)
    backup_path = Column(String(1000), nullable=True)
    file_size_bytes = Column(Integer, default=0)
    file_hash = Column(String(64), nullable=True)
    
    backed_up = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    
    original_modified_at = Column(DateTime, nullable=True)
    backed_up_at = Column(DateTime, nullable=True)
    
    snapshot = relationship("BackupSnapshot", back_populates="files")


class RestoreEvent(Base):
    __tablename__ = "restore_events"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("backup_snapshots.id"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    
    restore_type = Column(String(50), default="FULL")
    target_path = Column(String(500), nullable=True)
    
    status = Column(Enum(RestoreStatus), default=RestoreStatus.PENDING, nullable=False)
    
    files_to_restore = Column(Integer, default=0)
    files_restored = Column(Integer, default=0)
    files_failed = Column(Integer, default=0)
    files_missing = Column(Integer, default=0)
    
    hash_verification_passed = Column(Integer, default=0)
    hash_verification_failed = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    triggered_by = Column(String(100), nullable=True)
    initiated_by_user = Column(String(100), nullable=True)
    
    result_message = Column(Text, nullable=True)
    result_data = Column(JSON, nullable=True)
    
    snapshot = relationship("BackupSnapshot", back_populates="restore_events")
    host = relationship("Host")


# =============================================================================
# ISOLATION TRACKING MODELS
# =============================================================================

class IsolationEvent(Base):
    __tablename__ = "isolation_events"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    
    event_type = Column(String(50), nullable=False)
    
    isolation_policy = Column(String(50), nullable=True)
    ttl_minutes = Column(Integer, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    
    triggered_by = Column(String(100), nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=True)
    initiated_by_user = Column(String(100), nullable=True)
    
    dry_run = Column(Boolean, default=False)
    success = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    
    firewall_rules_applied = Column(JSON, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    host = relationship("Host", back_populates="isolation_events")


# =============================================================================
# SYSTEM CONFIGURATION
# =============================================================================

class SystemConfig(Base):
    __tablename__ = "system_config"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(String(1000), nullable=True)
    value_type = Column(String(50), default="string")
    description = Column(Text, nullable=True)
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(100), nullable=True)
"""
