"""SQLAlchemy models for RANSOMRUN platform."""

import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float,
    ForeignKey, Enum, JSON, Index
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


# =============================================================================
# AUTHENTICATION MODELS
# =============================================================================

class UserRole(str, enum.Enum):
    """User roles for authentication and authorization."""
    USER = "user"
    ADMIN = "admin"
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    BUSINESS = "business"  # C-level / business stakeholders


class AuthUser(Base):
    """User model for authentication and authorization."""
    __tablename__ = "auth_users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_email_active', 'email', 'is_active'),
    )


class DemoRequest(Base):
    """Demo request submissions from landing page."""
    __tablename__ = "demo_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    organization = Column(String(255), nullable=True)
    message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# =============================================================================
# CORE PLATFORM MODELS
# =============================================================================

class IsolationPolicy(str, enum.Enum):
    """Host isolation policies."""
    NONE = "NONE"
    FIREWALL_BLOCK = "FIREWALL_BLOCK"
    DISABLE_NIC = "DISABLE_NIC"
    HYBRID = "HYBRID"
    OUTBOUND_ONLY_BLOCK = "OUTBOUND_ONLY_BLOCK"
    RANSOMRUN_CONTROLLED = "RANSOMRUN_CONTROLLED"
    SEGMENT_QUARANTINE_SIM = "SEGMENT_QUARANTINE_SIM"


class BackupStatus(str, enum.Enum):
    """Backup snapshot status."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CORRUPTED = "CORRUPTED"


class RestoreStatus(str, enum.Enum):
    """Restore operation status."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ResponseExecutionStatus(str, enum.Enum):
    """Playbook action execution status."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class HostStatus(str, enum.Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


class RunStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class TaskStatus(str, enum.Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScenarioCategory(str, enum.Enum):
    CRYPTO = "crypto"
    LOCKER = "locker"
    WIPER = "wiper"
    EXFIL = "exfil"
    FAKE = "fake"
    MULTI_STAGE = "multi-stage"


class EventType(str, enum.Enum):
    RUN_CREATED = "RUN_CREATED"
    TASK_ASSIGNED = "TASK_ASSIGNED"
    TASK_SENT = "TASK_SENT"
    TASK_STARTED = "TASK_STARTED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    FILE_RENAMED = "FILE_RENAMED"
    FILE_QUARANTINED = "FILE_QUARANTINED"
    RANSOM_NOTE_CREATED = "RANSOM_NOTE_CREATED"
    VSSADMIN_EXECUTED = "VSSADMIN_EXECUTED"
    PERSISTENCE_CREATED = "PERSISTENCE_CREATED"
    EXFIL_PREPARED = "EXFIL_PREPARED"
    ALERT_RECEIVED = "ALERT_RECEIVED"
    PLAYBOOK_TRIGGERED = "PLAYBOOK_TRIGGERED"
    RESPONSE_TASK_CREATED = "RESPONSE_TASK_CREATED"
    RESPONSE_EXECUTED = "RESPONSE_EXECUTED"
    RUN_COMPLETED = "RUN_COMPLETED"
    RUN_FAILED = "RUN_FAILED"
    STOP_REQUESTED = "STOP_REQUESTED"
    STOP_EXECUTED = "STOP_EXECUTED"
    # Isolation & Recovery events
    HOST_ISOLATED = "HOST_ISOLATED"
    HOST_REISOLATED = "HOST_REISOLATED"
    HOST_DEISOLATED = "HOST_DEISOLATED"
    RECOVERY_STARTED = "RECOVERY_STARTED"
    RECOVERY_COMPLETED = "RECOVERY_COMPLETED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    # Snapshot events
    SNAPSHOT_CREATED = "SNAPSHOT_CREATED"
    SNAPSHOT_FAILED = "SNAPSHOT_FAILED"
    # Rollback events
    ROLLBACK_PLANNED = "ROLLBACK_PLANNED"
    ROLLBACK_APPROVED = "ROLLBACK_APPROVED"
    ROLLBACK_STARTED = "ROLLBACK_STARTED"
    ROLLBACK_FILE_RESTORED = "ROLLBACK_FILE_RESTORED"
    ROLLBACK_FILE_CONFLICT = "ROLLBACK_FILE_CONFLICT"
    ROLLBACK_FILE_FAILED = "ROLLBACK_FILE_FAILED"
    ROLLBACK_VERIFY_STARTED = "ROLLBACK_VERIFY_STARTED"
    ROLLBACK_VERIFY_COMPLETED = "ROLLBACK_VERIFY_COMPLETED"
    ROLLBACK_COMPLETED = "ROLLBACK_COMPLETED"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    # Timeline meta events
    RUN_STARTED = "RUN_STARTED"
    DETECTION_CONFIRMED = "DETECTION_CONFIRMED"
    CONTAINMENT_STARTED = "CONTAINMENT_STARTED"
    CONTAINMENT_COMPLETED = "CONTAINMENT_COMPLETED"
    # Containment & Isolation events (new)
    HOST_ISOLATION_REQUESTED = "HOST_ISOLATION_REQUESTED"
    HOST_ISOLATION_FAILED = "HOST_ISOLATION_FAILED"
    HOST_RESTORE_REQUESTED = "HOST_RESTORE_REQUESTED"
    HOST_NETWORK_RESTORED = "HOST_NETWORK_RESTORED"
    HOST_RESTORE_FAILED = "HOST_RESTORE_FAILED"
    PATH_BLOCK_REQUESTED = "PATH_BLOCK_REQUESTED"
    PATH_BLOCKED = "PATH_BLOCKED"
    QUARANTINE_REQUESTED = "QUARANTINE_REQUESTED"
    # Ransomware artifact data received
    RANSOMWARE_ARTIFACTS_RECEIVED = "RANSOMWARE_ARTIFACTS_RECEIVED"
    # Sensor detection events (Entropy & Honeyfile monitors)
    FILE_ENCRYPTED = "FILE_ENCRYPTED"
    FILE_ACCESSED = "FILE_ACCESSED"
    FILE_DELETED = "FILE_DELETED"
    ENTROPY_ALERT = "ENTROPY_ALERT"
    HONEYFILE_ALERT = "HONEYFILE_ALERT"


class FileActionType(str, enum.Enum):
    RENAMED = "RENAMED"
    FLAGGED = "FLAGGED"
    QUARANTINED = "QUARANTINED"
    COMPRESSED = "COMPRESSED"


class IOCType(str, enum.Enum):
    FILE_PATH = "FILE_PATH"
    CMD_LINE = "CMD_LINE"
    PROCESS_NAME = "PROCESS_NAME"
    REG_KEY = "REG_KEY"
    HASH = "HASH"
    NETWORK = "NETWORK"


class ProfileLabel(str, enum.Enum):
    LOUD_CRYPTO = "LOUD_CRYPTO"
    STEALTH_CRYPTO = "STEALTH_CRYPTO"
    LOCKER_STYLE = "LOCKER_STYLE"
    EXFIL_FOCUSED = "EXFIL_FOCUSED"
    WIPER_STYLE = "WIPER_STYLE"
    MULTI_STAGE = "MULTI_STAGE"
    TRAINING_ONLY = "TRAINING_ONLY"


# UserRole enum moved to authentication section above (line 18)
# Keeping this comment for reference - old values were: ANALYST, SENIOR_ANALYST, ADMIN


class CriticalityLevel(int, enum.Enum):
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ReportType(str, enum.Enum):
    GDPR = "GDPR"
    GENERIC = "Generic"
    MANAGEMENT_SUMMARY = "Management_Summary"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"


class IsolationPolicy(str, enum.Enum):
    FIREWALL_BLOCK = "FIREWALL_BLOCK"
    DISABLE_NIC = "DISABLE_NIC"
    HYBRID = "HYBRID"


class RecoveryPlanStatus(str, enum.Enum):
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RecoveryEventType(str, enum.Enum):
    RECOVERY_STARTED = "RECOVERY_STARTED"
    RECOVERY_TASK_CREATED = "RECOVERY_TASK_CREATED"
    RECOVERY_TASK_COMPLETED = "RECOVERY_TASK_COMPLETED"
    HOST_ISOLATED = "HOST_ISOLATED"
    HOST_REISOLATED = "HOST_REISOLATED"
    HOST_DEISOLATED = "HOST_DEISOLATED"
    USER_REENABLED = "USER_REENABLED"
    FILES_RESTORED_FROM_QUARANTINE = "FILES_RESTORED_FROM_QUARANTINE"


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    agent_id = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    status = Column(Enum(HostStatus), default=HostStatus.UNKNOWN)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Isolation fields
    is_isolated = Column(Boolean, default=False)
    isolation_policy = Column(Enum(IsolationPolicy), nullable=True)
    isolation_ttl_minutes = Column(Integer, nullable=True)  # Auto-unisolate after X minutes
    isolation_expires_at = Column(DateTime, nullable=True)
    last_isolated_at = Column(DateTime, nullable=True)
    last_deisolated_at = Column(DateTime, nullable=True)
    
    # Response automation settings
    allow_auto_response = Column(Boolean, default=True, nullable=False)
    quarantine_status = Column(String(50), nullable=True)  # CLEAN, SUSPECTED, QUARANTINED, RECOVERING

    # Relationships
    runs = relationship("Run", back_populates="host")
    tasks = relationship("Task", back_populates="host")
    alerts = relationship("Alert", back_populates="host")
    recovery_plans = relationship("RecoveryPlan", back_populates="host")
    backup_snapshots = relationship("BackupSnapshot", back_populates="host", order_by="BackupSnapshot.created_at.desc()")
    isolation_events = relationship("IsolationEvent", back_populates="host", order_by="IsolationEvent.timestamp.desc()")


class Scenario(Base):
    """
    Ransomware scenario definition.
    
    Scenarios can be built-in (seeded) or custom (user-created).
    The config JSON defines the full ransomware behavior simulation parameters.
    
    IMPORTANT: All scenarios are SIMULATION ONLY - no real encryption or malware.
    """
    __tablename__ = "scenarios"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(Enum(ScenarioCategory), default=ScenarioCategory.CRYPTO)
    config = Column(JSON, nullable=True)  # Detailed scenario configuration
    
    # Custom scenario fields
    is_custom = Column(Boolean, default=False)  # True for user-created scenarios
    created_by = Column(String(100), nullable=True)  # Username or "system" for built-in
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    runs = relationship("Run", back_populates="scenario")


class Run(Base):
    __tablename__ = "runs"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False)
    status = Column(Enum(RunStatus), default=RunStatus.PENDING)
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    host = relationship("Host", back_populates="runs")
    scenario = relationship("Scenario", back_populates="runs")
    tasks = relationship("Task", back_populates="run")
    alerts = relationship("Alert", back_populates="run")
    events = relationship("RunEvent", back_populates="run", order_by="RunEvent.timestamp")
    affected_files = relationship("AffectedFile", back_populates="run")
    metrics = relationship("Metric", back_populates="run")
    iocs = relationship("IOC", back_populates="run")


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    type = Column(String(100), nullable=False)
    parameters = Column(JSON, nullable=True)
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    result_message = Column(Text, nullable=True)

    # Relationships
    run = relationship("Run", back_populates="tasks")
    host = relationship("Host", back_populates="tasks")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    rule_id = Column(String(50), nullable=False, index=True)
    rule_description = Column(String(500), nullable=True)
    agent_name = Column(String(255), nullable=True)
    severity = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)
    raw = Column(JSON, nullable=True)

    # Relationships
    host = relationship("Host", back_populates="alerts")
    run = relationship("Run", back_populates="alerts")


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
    playbook_actions = relationship("PlaybookAction", back_populates="playbook", order_by="PlaybookAction.order", cascade="all, delete-orphan")
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
    playbook = relationship("Playbook", back_populates="playbook_actions")


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


class RunEvent(Base):
    """Timeline events for a simulation run."""
    __tablename__ = "run_events"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    event_type = Column(Enum(EventType), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    details = Column(JSON, nullable=True)

    # Relationships
    run = relationship("Run", back_populates="events")
    host = relationship("Host")


class AffectedFile(Base):
    """Files affected during a simulation run."""
    __tablename__ = "affected_files"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    original_path = Column(String(1024), nullable=False)
    new_path = Column(String(1024), nullable=True)
    action_type = Column(Enum(FileActionType), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("Run", back_populates="affected_files")
    host = relationship("Host")


class Metric(Base):
    """Metrics captured during a simulation run."""
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    name = Column(String(100), nullable=False)
    value = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("Run", back_populates="metrics")
    host = relationship("Host")


class IOC(Base):
    """Indicators of Compromise captured during simulation."""
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    ioc_type = Column(Enum(IOCType), nullable=False)
    value = Column(String(2048), nullable=False)
    context = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("Run", back_populates="iocs")
    host = relationship("Host")


class ELKConfig(Base):
    """ELK/Elasticsearch SIEM configuration storage."""
    __tablename__ = "elk_config"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False)
    username = Column(String(100), nullable=True)
    password = Column(String(255), nullable=True)  # Should be encrypted in production
    api_key = Column(String(1024), nullable=True)
    index_alerts = Column(String(255), default='.alerts-security.alerts-*')
    index_logs = Column(String(255), default='logs-*')
    enabled = Column(Boolean, default=True)
    last_sync = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# =============================================================================
# ADVANCED FEATURE MODELS
# =============================================================================

class User(Base):
    """User/Analyst model for skill tracking (legacy - use AuthUser for authentication)."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.ANALYST, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    ir_sessions = relationship("IRSession", back_populates="user")
    skill_profile = relationship("UserSkillProfile", back_populates="user", uselist=False)
    run_feedbacks = relationship("RunFeedback", back_populates="user")


class BehaviorProfile(Base):
    """Behavior DNA fingerprint for a simulation run."""
    __tablename__ = "behavior_profiles"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), unique=True, nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    techniques = Column(JSON, nullable=True)  # List of MITRE techniques
    actions_sequence = Column(JSON, nullable=True)  # Ordered list of events
    intensity_score = Column(Float, default=0.0)  # 0-100
    stealthiness_score = Column(Float, default=0.0)  # 0-100
    dna_vector = Column(JSON, nullable=True)  # Compact behavior fingerprint
    profile_label = Column(Enum(ProfileLabel), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("Run", backref="behavior_profile")
    host = relationship("Host")


class WhatIfScenario(Base):
    """Counterfactual defense analysis scenario."""
    __tablename__ = "whatif_scenarios"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    assumptions = Column(JSON, nullable=True)  # Hypothetical changes
    recalculated_metrics = Column(JSON, nullable=True)  # New estimated metrics
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("Run", backref="whatif_scenarios")


class IRSession(Base):
    """Incident Response session linking users to runs."""
    __tablename__ = "ir_sessions"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    actions_taken = Column(JSON, nullable=True)  # List of actions user took

    # Relationships
    run = relationship("Run", backref="ir_sessions")
    user = relationship("User", back_populates="ir_sessions")


class UserSkillProfile(Base):
    """Aggregated skill metrics for a user."""
    __tablename__ = "user_skill_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    metrics = Column(JSON, nullable=True)  # Aggregated metrics
    strengths = Column(Text, nullable=True)
    weaknesses = Column(Text, nullable=True)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="skill_profile")


class RunFeedback(Base):
    """Coach feedback for a simulation run."""
    __tablename__ = "run_feedbacks"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    positives = Column(Text, nullable=True)  # Bullet-point style
    negatives = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("Run", backref="feedbacks")
    user = relationship("User", back_populates="run_feedbacks")


class BusinessImpact(Base):
    """Business impact assessment for a simulation run."""
    __tablename__ = "business_impacts"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    business_unit = Column(String(100), default="Generic")
    criticality_level = Column(Integer, default=3)  # 1-5
    assumed_cost_per_hour = Column(Float, default=500.0)
    estimated_downtime_hours = Column(Float, default=0.0)
    estimated_data_recovery_hours = Column(Float, default=0.0)
    data_sensitivity_level = Column(Integer, default=3)  # 1-5
    estimated_total_cost = Column(Float, default=0.0)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Actual recovery metrics (populated after recovery completes)
    actual_recovery_hours = Column(Float, nullable=True)
    actual_total_cost = Column(Float, nullable=True)

    # Relationships
    run = relationship("Run", backref="business_impact")


class ComplianceReport(Base):
    """Compliance/regulatory incident report."""
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    report_type = Column(Enum(ReportType), default=ReportType.GENERIC)
    summary = Column(Text, nullable=True)
    incident_start = Column(DateTime, nullable=True)
    incident_detection = Column(DateTime, nullable=True)
    incident_containment = Column(DateTime, nullable=True)
    incident_deisolation = Column(DateTime, nullable=True)  # When host was de-isolated
    incident_recovery_completed = Column(DateTime, nullable=True)  # When recovery finished
    data_subjects_affected_estimate = Column(Integer, nullable=True)
    personal_data_involved = Column(Boolean, nullable=True)
    regulatory_notification_required = Column(Boolean, nullable=True)
    risk_to_individuals = Column(String(50), nullable=True)  # Low, Moderate, High
    mitigation_recommendations = Column(Text, nullable=True)
    containment_actions_summary = Column(Text, nullable=True)  # Summary of containment actions
    recovery_actions_summary = Column(Text, nullable=True)  # Summary of recovery actions
    generated_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    run = relationship("Run", backref="compliance_reports")


class RecoveryPlan(Base):
    """Recovery plan for an incident run."""
    __tablename__ = "recovery_plans"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    status = Column(Enum(RecoveryPlanStatus), default=RecoveryPlanStatus.PLANNED)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    run = relationship("Run", backref="recovery_plans")
    host = relationship("Host", back_populates="recovery_plans")
    events = relationship("RecoveryEvent", back_populates="recovery_plan", order_by="RecoveryEvent.timestamp")


class RecoveryEvent(Base):
    """Events during recovery process."""
    __tablename__ = "recovery_events"

    id = Column(Integer, primary_key=True, index=True)
    recovery_plan_id = Column(Integer, ForeignKey("recovery_plans.id"), nullable=False, index=True)
    event_type = Column(Enum(RecoveryEventType), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(JSON, nullable=True)

    # Relationships
    recovery_plan = relationship("RecoveryPlan", back_populates="events")


class DetectionCursor(Base):
    """Cursor state for detection engine polling."""
    __tablename__ = "detection_cursors"

    id = Column(Integer, primary_key=True, index=True)
    engine_id = Column(String(50), unique=True, nullable=False, index=True)
    last_timestamp = Column(String(50), nullable=True)
    search_after_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SOARResponse(Base):
    """SOAR response action history."""
    __tablename__ = "soar_responses"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True, index=True)
    action_type = Column(String(50), nullable=False)  # isolate_host, kill_process, etc.
    action_params = Column(JSON, nullable=True)
    dry_run = Column(Boolean, default=False)
    status = Column(String(20), default='pending')  # pending, success, failed
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    executed_at = Column(DateTime, nullable=True)

    # Relationships
    alert = relationship("Alert")
    host = relationship("Host")


# MITRE ATT&CK Mapping (static dictionary)
MITRE_MAPPING = {
    "100101": {"technique": "T1490", "name": "Inhibit System Recovery"},
    "100102": {"technique": "T1486", "name": "Data Encrypted for Impact"},
    "100103": {"technique": "T1491", "name": "Defacement"},
    "100104": {"technique": "T1489", "name": "Service Stop"},
    "100105": {"technique": "T1562", "name": "Impair Defenses"},
    "100106": {"technique": "T1059", "name": "Command and Scripting Interpreter"},
    "100107": {"technique": "T1047", "name": "Windows Management Instrumentation"},
    "100108": {"technique": "T1112", "name": "Modify Registry"},
}

# Extended MITRE mapping for internal events
EVENT_TO_MITRE = {
    "VSSADMIN_EXECUTED": {"technique": "T1490", "name": "Inhibit System Recovery"},
    "FILE_RENAMED": {"technique": "T1486", "name": "Data Encrypted for Impact"},
    "RANSOM_NOTE_CREATED": {"technique": "T1486", "name": "Data Encrypted for Impact"},
    "PERSISTENCE_CREATED": {"technique": "T1547", "name": "Boot or Logon Autostart Execution"},
    "EXFIL_PREPARED": {"technique": "T1560", "name": "Archive Collected Data"},
    "FILE_QUARANTINED": {"technique": "T1485", "name": "Data Destruction"},
}


# =============================================================================
# PHISHING AWARENESS SIMULATOR MODELS
# =============================================================================

class CampaignStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    ENDED = "ENDED"


class DeliveryMode(str, enum.Enum):
    IN_APP = "IN_APP"
    MAIL_SINK = "MAIL_SINK"
    SMTP = "SMTP"


class PhishingEventType(str, enum.Enum):
    CREATED = "CREATED"
    SENT = "SENT"
    OPENED = "OPENED"
    CLICKED = "CLICKED"
    DOWNLOADED = "DOWNLOADED"
    EXECUTED = "EXECUTED"
    SIMULATION_STARTED = "SIMULATION_STARTED"
    DETECTED = "DETECTED"
    CONTAINED = "CONTAINED"
    REPORTED = "REPORTED"


class PhishingCampaign(Base):
    """A phishing awareness training campaign."""
    __tablename__ = "phishing_campaigns"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    template_key = Column(String(100), nullable=True)
    status = Column(Enum(CampaignStatus), default=CampaignStatus.DRAFT)
    delivery_mode = Column(Enum(DeliveryMode), default=DeliveryMode.IN_APP)
    target_group_tag = Column(String(100), nullable=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=True)
    created_by = Column(String(100), default="admin")
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    
    recipients = relationship("PhishingRecipient", back_populates="campaign", cascade="all, delete-orphan")
    messages = relationship("PhishingMessage", back_populates="campaign", cascade="all, delete-orphan")
    scenario = relationship("Scenario")


class PhishingRecipient(Base):
    """A recipient in a phishing campaign."""
    __tablename__ = "phishing_recipients"
    
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("phishing_campaigns.id"), nullable=False)
    display_name = Column(String(200), nullable=False)
    email = Column(String(200), nullable=False)
    department = Column(String(100), nullable=True)
    allowlisted = Column(Boolean, default=False)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    
    campaign = relationship("PhishingCampaign", back_populates="recipients")
    messages = relationship("PhishingMessage", back_populates="recipient")
    host = relationship("Host")


class PhishingMessage(Base):
    """A generated phishing training message."""
    __tablename__ = "phishing_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("phishing_campaigns.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("phishing_recipients.id"), nullable=False)
    subject = Column(String(500), nullable=False)
    body_html = Column(Text, nullable=False)
    body_text = Column(Text, nullable=True)
    tracking_token = Column(String(64), unique=True, nullable=False, index=True)
    delivery_mode = Column(Enum(DeliveryMode), default=DeliveryMode.IN_APP)
    status = Column(String(50), default="PENDING")
    created_at = Column(DateTime, default=datetime.utcnow)
    sent_at = Column(DateTime, nullable=True)
    is_opened = Column(Boolean, default=False)
    is_clicked = Column(Boolean, default=False)
    is_downloaded = Column(Boolean, default=False)
    is_executed = Column(Boolean, default=False)
    is_reported = Column(Boolean, default=False)
    opened_at = Column(DateTime, nullable=True)
    clicked_at = Column(DateTime, nullable=True)
    downloaded_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    reported_at = Column(DateTime, nullable=True)
    
    # Link to simulation run triggered by this phishing message
    simulation_run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    
    # Token expiry for security
    token_expires_at = Column(DateTime, nullable=True)
    
    campaign = relationship("PhishingCampaign", back_populates="messages")
    recipient = relationship("PhishingRecipient", back_populates="messages")
    events = relationship("PhishingEvent", back_populates="message", cascade="all, delete-orphan")
    simulation_run = relationship("Run", foreign_keys=[simulation_run_id])


class PhishingEvent(Base):
    """Tracks individual events for a phishing message."""
    __tablename__ = "phishing_events"
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("phishing_messages.id"), nullable=False)
    event_type = Column(Enum(PhishingEventType), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(500), nullable=True)
    hostname = Column(String(255), nullable=True)
    meta_json = Column(JSON, nullable=True)
    
    message = relationship("PhishingMessage", back_populates="events")


class PhishingTemplate(Base):
    """Reusable phishing email templates stored in database."""
    __tablename__ = "phishing_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    key = Column(String(100), unique=True, nullable=False, index=True)
    category = Column(String(100), default="general")
    description = Column(Text, nullable=True)
    subject = Column(String(500), nullable=False)
    body_html = Column(Text, nullable=False)
    body_text = Column(Text, nullable=True)
    variables = Column(JSON, nullable=True)  # List of variable names used in template
    has_attachment = Column(Boolean, default=False)
    attachment_name = Column(String(255), nullable=True)
    landing_page_type = Column(String(50), default="document")  # document, login, invoice, etc.
    created_by = Column(String(100), default="system")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class PhishingSettings(Base):
    """Global settings for phishing training system."""
    __tablename__ = "phishing_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    setting_key = Column(String(100), unique=True, nullable=False, index=True)
    setting_value = Column(Text, nullable=True)
    setting_type = Column(String(20), default="string")  # string, json, int, bool
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(100), nullable=True)


# =============================================================================
# BACKUP & RECOVERY MODELS
# =============================================================================

class BackupSnapshot(Base):
    """File-level backup snapshot of a host."""
    __tablename__ = "backup_snapshots"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    
    # Legacy fields
    snapshot_name = Column(String(255), nullable=True)
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
    
    # NEW fields for backup plan integration
    plan_id = Column(Integer, ForeignKey("backup_plans.id"), nullable=True, index=True)
    job_id = Column(Integer, ForeignKey("backup_jobs.id"), nullable=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    
    snapshot_time = Column(DateTime, default=datetime.utcnow, nullable=True)
    storage_path = Column(String(500), nullable=True)
    file_count = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    folder_count = Column(Integer, default=0)
    manifest_path = Column(String(500), nullable=True)
    integrity_status = Column(String(20), default="unchecked")
    integrity_checked_at = Column(DateTime, nullable=True)
    integrity_errors = Column(JSON, nullable=True)
    source_paths_json = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    deleted = Column(Boolean, default=False)
    deleted_at = Column(DateTime, nullable=True)
    
    host = relationship("Host", back_populates="backup_snapshots")
    files = relationship("BackupFile", back_populates="snapshot", cascade="all, delete-orphan")
    restore_events = relationship("RestoreEvent", back_populates="snapshot")


class BackupFile(Base):
    """Individual file within a backup snapshot."""
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
    """Tracks restore operations from backup snapshots."""
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
    """Tracks host isolation/de-isolation events for audit trail."""
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
    """Global system configuration for response automation."""
    __tablename__ = "system_config"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(String(1000), nullable=True)
    value_type = Column(String(50), default="string")
    description = Column(Text, nullable=True)
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(100), nullable=True)


# =============================================================================
# AUTO ROLLBACK MODELS
# =============================================================================

class RollbackPlanStatus(str, enum.Enum):
    """Status of a rollback plan."""
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class RollbackActionType(str, enum.Enum):
    """Type of file action during rollback."""
    RESTORE = "RESTORE"
    SKIP = "SKIP"
    CONFLICT_MOVE = "CONFLICT_MOVE"
    CLEANUP_EXTENSION = "CLEANUP_EXTENSION"
    FAIL = "FAIL"


class RollbackPlan(Base):
    """
    AutoRollback plan for restoring files from backup snapshots.
    
    SAFETY: Only operates on configured safe paths (lab directories).
    """
    __tablename__ = "rollback_plans"
    __table_args__ = (
        Index('idx_rollback_host_status', 'host_id', 'status'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("backup_snapshots.id"), nullable=True, index=True)
    
    # Plan configuration
    status = Column(Enum(RollbackPlanStatus), default=RollbackPlanStatus.DRAFT, nullable=False)
    dry_run = Column(Boolean, default=False, nullable=False)
    
    # Safe paths configuration (JSON array of allowed paths)
    safe_paths = Column(JSON, nullable=True)  # ["C:\\RansomTest", "C:\\RansomLab"]
    
    # Conflict policy
    conflict_policy = Column(String(50), default="QUARANTINE")  # QUARANTINE, OVERWRITE, SKIP
    cleanup_extensions = Column(JSON, nullable=True)  # [".locked", ".encrypted", ".dwcrypt"]
    
    # Approval workflow
    requires_approval = Column(Boolean, default=True, nullable=False)
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    
    # Execution tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by = Column(String(100), default="system")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Plan summary
    total_files = Column(Integer, default=0)
    files_to_restore = Column(Integer, default=0)
    files_to_skip = Column(Integer, default=0)
    files_with_conflicts = Column(Integer, default=0)
    
    # Execution lock (prevent parallel execution on same host)
    execution_lock = Column(String(64), nullable=True, unique=True)
    
    # Config JSON for additional settings
    config_json = Column(JSON, nullable=True)
    
    # Relationships
    host = relationship("Host")
    run = relationship("Run")
    snapshot = relationship("BackupSnapshot")
    file_actions = relationship("RollbackFileAction", back_populates="plan", cascade="all, delete-orphan")
    report = relationship("RollbackReport", back_populates="plan", uselist=False)


class RollbackFileAction(Base):
    """
    Individual file action within a rollback plan.
    Tracks before/after state for audit trail.
    """
    __tablename__ = "rollback_file_actions"
    __table_args__ = (
        Index('idx_rollback_file_plan', 'plan_id', 'action_type'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    plan_id = Column(Integer, ForeignKey("rollback_plans.id"), nullable=False, index=True)
    
    # File information
    original_path = Column(String(1000), nullable=False)
    backup_path = Column(String(1000), nullable=True)
    
    # Action details
    action_type = Column(Enum(RollbackActionType), nullable=False)
    action_reason = Column(String(500), nullable=True)
    
    # Hash verification
    before_hash = Column(String(64), nullable=True)  # Current file hash before restore
    expected_hash = Column(String(64), nullable=True)  # Expected hash from backup
    after_hash = Column(String(64), nullable=True)  # Actual hash after restore
    hash_verified = Column(Boolean, nullable=True)
    
    # Execution status
    executed = Column(Boolean, default=False)
    executed_at = Column(DateTime, nullable=True)
    success = Column(Boolean, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Conflict handling
    conflict_backup_path = Column(String(1000), nullable=True)  # Where conflicting file was moved
    
    # Relationships
    plan = relationship("RollbackPlan", back_populates="file_actions")


class RollbackReport(Base):
    """
    Summary report for a completed rollback operation.
    """
    __tablename__ = "rollback_reports"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    plan_id = Column(Integer, ForeignKey("rollback_plans.id"), nullable=False, unique=True, index=True)
    
    # Summary counts
    files_restored = Column(Integer, default=0)
    files_skipped = Column(Integer, default=0)
    files_conflict_moved = Column(Integer, default=0)
    files_cleaned_extensions = Column(Integer, default=0)
    files_failed = Column(Integer, default=0)
    
    # Hash verification summary
    hash_verifications_passed = Column(Integer, default=0)
    hash_verifications_failed = Column(Integer, default=0)
    
    # Timing
    elapsed_seconds = Column(Float, default=0.0)
    
    # Final status
    final_status = Column(String(20), nullable=False)  # SUCCESS, PARTIAL, FAILED
    
    # Detailed summary JSON
    summary_json = Column(JSON, nullable=True)
    
    # Errors encountered
    errors = Column(JSON, nullable=True)  # List of error messages
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    plan = relationship("RollbackPlan", back_populates="report")


# =============================================================================
# IR (INCIDENT RESPONSE) TIMELINE & LESSONS LEARNED MODELS
# =============================================================================

class IRPhase(str, enum.Enum):
    """Standard IR lifecycle phases."""
    PREPARATION = "PREPARATION"
    IDENTIFICATION = "IDENTIFICATION"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    LESSONS_LEARNED = "LESSONS_LEARNED"


class IRPhaseStatusType(str, enum.Enum):
    """Status of an IR phase."""
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"


class ActionItemPriority(str, enum.Enum):
    """Priority levels for action items."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionItemStatus(str, enum.Enum):
    """Status of action items."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    DEFERRED = "DEFERRED"


class IRPhaseStatus(Base):
    """
    Tracks the status of each IR phase for a simulation run.
    Each run can have up to 6 phase status records (one per phase).
    """
    __tablename__ = "ir_phase_status"
    __table_args__ = (
        Index('idx_ir_phase_run', 'run_id', 'phase'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    phase = Column(Enum(IRPhase), nullable=False)
    status = Column(Enum(IRPhaseStatusType), default=IRPhaseStatusType.NOT_STARTED)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    
    # Metrics for this phase
    duration_seconds = Column(Float, nullable=True)
    event_count = Column(Integer, default=0)
    
    # Relationships
    run = relationship("Run")


class LessonsLearned(Base):
    """
    Lessons learned summary for a simulation run.
    Generated automatically or manually after run completion.
    """
    __tablename__ = "lessons_learned"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, unique=True, index=True)
    
    # Summary content
    summary = Column(Text, nullable=True)  # 5-10 line summary
    what_went_well = Column(JSON, nullable=True)  # List of bullet points
    what_went_wrong = Column(JSON, nullable=True)  # List of bullet points
    
    # Key metrics
    time_to_detect_seconds = Column(Float, nullable=True)  # TTD
    time_to_contain_seconds = Column(Float, nullable=True)  # TTC
    time_to_recover_seconds = Column(Float, nullable=True)  # TTR
    total_duration_seconds = Column(Float, nullable=True)
    
    # Impact metrics
    affected_files_count = Column(Integer, default=0)
    affected_endpoints_count = Column(Integer, default=0)
    high_severity_alerts_count = Column(Integer, default=0)
    total_alerts_count = Column(Integer, default=0)
    
    # MITRE techniques observed
    mitre_techniques = Column(JSON, nullable=True)  # List of technique IDs
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    run = relationship("Run")
    action_items = relationship("LessonsActionItem", back_populates="lessons_learned", cascade="all, delete-orphan")


class LessonsActionItem(Base):
    """
    Individual action item from lessons learned.
    Tracks remediation tasks and improvements.
    """
    __tablename__ = "lessons_action_items"
    __table_args__ = (
        Index('idx_action_item_run', 'run_id'),
        Index('idx_action_item_status', 'status'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    lessons_learned_id = Column(Integer, ForeignKey("lessons_learned.id"), nullable=False, index=True)
    
    # Action item details
    item = Column(Text, nullable=False)  # Description of the action
    priority = Column(Enum(ActionItemPriority), default=ActionItemPriority.MEDIUM)
    category = Column(String(100), nullable=True)  # detection, containment, process, training, etc.
    
    # Assignment
    owner = Column(String(255), nullable=True)  # Assigned owner (placeholder)
    due_date = Column(DateTime, nullable=True)
    
    # Status tracking
    status = Column(Enum(ActionItemStatus), default=ActionItemStatus.OPEN)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    lessons_learned = relationship("LessonsLearned", back_populates="action_items")


# =============================================================================
# NETWORK ISOLATION STATE MODELS (Robust Isolation/Restore)
# =============================================================================

class IsolationMode(str, enum.Enum):
    """Network isolation mode."""
    ADAPTER = "adapter"      # Disable network adapters
    FIREWALL = "firewall"    # Firewall rules block all except backend
    HYBRID = "hybrid"        # Both adapter disable + firewall rules


class HostIsolationState(Base):
    """
    Stores the pre-isolation network state for reliable restoration.
    Captures adapter configuration, IPs, DNS, gateway before isolation.
    """
    __tablename__ = "host_isolation_states"
    __table_args__ = (
        Index('idx_isolation_state_host_active', 'host_id', 'active'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    
    # Isolation configuration
    mode = Column(Enum(IsolationMode), nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    
    # Pre-isolation network state (comprehensive JSON)
    pre_state_json = Column(JSON, nullable=True)
    # Structure:
    # {
    #   "adapters": [
    #     {
    #       "name": "Ethernet",
    #       "interface_index": 5,
    #       "interface_description": "Intel(R) Ethernet",
    #       "mac_address": "AA-BB-CC-DD-EE-FF",
    #       "status": "Up",
    #       "was_enabled": true,
    #       "ip_addresses": ["192.168.1.100"],
    #       "subnet_masks": ["255.255.255.0"],
    #       "default_gateway": "192.168.1.1",
    #       "dns_servers": ["8.8.8.8", "8.8.4.4"],
    #       "dhcp_enabled": true
    #     }
    #   ],
    #   "default_routes": [...],
    #   "firewall_profile_states": {...}
    # }
    
    # Post-isolation state for verification
    post_isolation_state_json = Column(JSON, nullable=True)
    
    # Post-restore state for verification
    post_restore_state_json = Column(JSON, nullable=True)
    
    # Backend allow configuration
    backend_ip = Column(String(45), nullable=True)
    backend_ports = Column(JSON, nullable=True)  # [8000, 443, 9200, 5044]
    
    # Firewall rules created (for cleanup)
    firewall_rules = Column(JSON, nullable=True)  # ["RANSOMRUN_BLOCK_OUT", ...]
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    isolated_at = Column(DateTime, nullable=True)
    restored_at = Column(DateTime, nullable=True)
    
    # User/trigger info
    triggered_by = Column(String(100), nullable=True)  # "manual", "playbook", "auto"
    initiated_by_user = Column(String(100), nullable=True)
    
    # Relationships
    host = relationship("Host")
    run = relationship("Run")
    alert = relationship("Alert")


class ResponseActionLog(Base):
    """
    Detailed log of response actions (isolate, restore, etc.) with full output.
    Provides audit trail and debugging information.
    """
    __tablename__ = "response_action_logs"
    __table_args__ = (
        Index('idx_response_log_host', 'host_id', 'action'),
        Index('idx_response_log_time', 'started_at'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    isolation_state_id = Column(Integer, ForeignKey("host_isolation_states.id"), nullable=True)
    
    # Action details
    action = Column(String(50), nullable=False)  # "isolate_host", "restore_network", etc.
    action_params = Column(JSON, nullable=True)
    
    # Status
    status = Column(String(20), default="pending", nullable=False)  # pending, running, success, failed, partial
    dry_run = Column(Boolean, default=False, nullable=False)
    
    # Execution details
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    
    # Result data
    success = Column(Boolean, nullable=True)
    message = Column(Text, nullable=True)
    
    # Command execution details
    commands_executed = Column(JSON, nullable=True)  # List of commands run
    stdout = Column(Text, nullable=True)
    stderr = Column(Text, nullable=True)
    exit_codes = Column(JSON, nullable=True)
    
    # State snapshots
    pre_state = Column(JSON, nullable=True)
    post_state = Column(JSON, nullable=True)
    
    # Verification results
    verification_passed = Column(Boolean, nullable=True)
    verification_details = Column(JSON, nullable=True)
    
    # Errors
    errors = Column(JSON, nullable=True)  # List of error messages
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    agent_version = Column(String(50), nullable=True)
    
    # Relationships
    host = relationship("Host")
    run = relationship("Run")
    alert = relationship("Alert")
    isolation_state = relationship("HostIsolationState")
