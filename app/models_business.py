"""Business Portal models for RansomRun platform.

These models support the C-level/Business stakeholder portal features:
- Executive Dashboard
- ROI Calculator
- Compliance Reporting
- Training Programs
- Tenant Management
- Feedback Center
- RTO/RPO Tracking
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
# BUSINESS SETTINGS & CONFIGURATION
# =============================================================================

class BusinessSettings(Base):
    """Business configuration settings for cost calculations and metrics."""
    __tablename__ = "business_settings"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=True, index=True)
    
    # Cost configuration
    hourly_revenue = Column(Float, default=10000.0)  # Revenue lost per hour of downtime
    hourly_it_cost = Column(Float, default=500.0)  # IT staff cost per hour
    baseline_downtime_hours = Column(Float, default=4.0)  # Baseline expected downtime
    
    # RTO/RPO targets
    target_rto_minutes = Column(Integer, default=60)  # Target Recovery Time Objective
    target_rpo_minutes = Column(Integer, default=15)  # Target Recovery Point Objective
    
    # Risk configuration
    risk_weight_critical = Column(Integer, default=10)
    risk_weight_high = Column(Integer, default=6)
    risk_weight_medium = Column(Integer, default=3)
    risk_weight_low = Column(Integer, default=1)
    risk_weight_failed_run = Column(Integer, default=5)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# =============================================================================
# ORGANIZATION / TENANT MANAGEMENT
# =============================================================================

class OrganizationPlan(str, enum.Enum):
    """Organization subscription plans."""
    LAB = "LAB"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


class Organization(Base):
    """Organization/tenant for multi-tenancy support."""
    __tablename__ = "organizations"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    industry = Column(String(100), nullable=True)
    plan = Column(Enum(OrganizationPlan), default=OrganizationPlan.LAB)
    
    # Contact info
    contact_email = Column(String(255), nullable=True)
    contact_name = Column(String(255), nullable=True)
    
    # Usage tracking
    max_endpoints = Column(Integer, default=10)
    max_users = Column(Integer, default=5)
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("OrganizationUser", back_populates="organization", cascade="all, delete-orphan")


class OrganizationUser(Base):
    """Links users to organizations with roles."""
    __tablename__ = "organization_users"
    __table_args__ = (
        Index('idx_org_user', 'org_id', 'user_id'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=False)
    role_in_org = Column(String(50), default="member")  # owner, admin, member
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")


# =============================================================================
# ROI CALCULATOR
# =============================================================================

class RoiCalcHistory(Base):
    """History of ROI calculations performed by business users."""
    __tablename__ = "roi_calc_history"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=False, index=True)
    
    # Input parameters
    endpoints_count = Column(Integer, default=100)
    avg_hourly_revenue = Column(Float, default=10000.0)
    avg_it_cost_per_hour = Column(Float, default=500.0)
    typical_downtime_hours = Column(Float, default=4.0)
    improvement_percent = Column(Float, default=50.0)
    
    # Calculated outputs
    potential_loss_per_incident = Column(Float, nullable=True)
    potential_savings = Column(Float, nullable=True)
    time_saved_per_exercise = Column(Float, nullable=True)
    roi_percentage = Column(Float, nullable=True)
    
    # Metadata
    calculation_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# =============================================================================
# TRAINING & READINESS
# =============================================================================

class TrainingCampaignStatus(str, enum.Enum):
    """Status of a training campaign."""
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class TrainingCampaign(Base):
    """Training/drill campaign for ransomware readiness."""
    __tablename__ = "training_campaigns"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    status = Column(Enum(TrainingCampaignStatus), default=TrainingCampaignStatus.DRAFT)
    
    # Campaign period
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    
    # Target configuration
    target_hosts = Column(JSON, nullable=True)  # List of host IDs or "all"
    target_scenarios = Column(JSON, nullable=True)  # List of scenario IDs
    
    # Goals
    target_completion_rate = Column(Float, default=80.0)  # Target % of participants to complete
    target_response_time_minutes = Column(Integer, default=30)  # Target response time
    
    created_by = Column(Integer, ForeignKey("auth_users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    results = relationship("TrainingResult", back_populates="campaign", cascade="all, delete-orphan")


class TrainingResult(Base):
    """Individual training/drill results for participants."""
    __tablename__ = "training_results"
    __table_args__ = (
        Index('idx_training_campaign_host', 'campaign_id', 'host_id'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("training_campaigns.id"), nullable=False)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    
    # Performance metrics
    score = Column(Float, default=0.0)  # 0-100 score
    time_to_detect_seconds = Column(Float, nullable=True)
    time_to_contain_seconds = Column(Float, nullable=True)
    time_to_recover_seconds = Column(Float, nullable=True)
    
    # Status
    completed = Column(Boolean, default=False)
    passed = Column(Boolean, default=False)  # Met the campaign goals
    
    # Feedback
    notes = Column(Text, nullable=True)
    strengths = Column(JSON, nullable=True)
    improvements = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    campaign = relationship("TrainingCampaign", back_populates="results")


# =============================================================================
# PILOT & FEEDBACK
# =============================================================================

class Feedback(Base):
    """User feedback for pilot program and general improvements."""
    __tablename__ = "business_feedback"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=True)
    
    # Feedback content
    rating = Column(Integer, default=3)  # 1-5 stars
    category = Column(String(100), nullable=True)  # ui, performance, features, etc.
    
    # Open-ended feedback
    what_was_unclear = Column(Text, nullable=True)
    feature_requests = Column(Text, nullable=True)
    would_pay_for = Column(Text, nullable=True)
    general_comments = Column(Text, nullable=True)
    
    # NPS-style question
    would_recommend = Column(Integer, nullable=True)  # 1-10 scale
    
    created_at = Column(DateTime, default=datetime.utcnow)


class PilotConfig(Base):
    """Configuration for pilot program tracking."""
    __tablename__ = "pilot_config"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Pilot parameters
    target_users_count = Column(Integer, default=20)
    duration_days = Column(Integer, default=14)
    success_threshold = Column(Float, default=0.70)  # 70% satisfaction
    
    # Status
    is_active = Column(Boolean, default=True)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    
    # Goals
    conversion_target = Column(Float, default=0.30)  # 30% conversion rate target
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# =============================================================================
# BUSINESS AUDIT LOG
# =============================================================================

class BusinessAuditLog(Base):
    """Audit trail for business user actions."""
    __tablename__ = "business_audit_log"
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_timestamp', 'timestamp'),
        {'extend_existing': True}
    )
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=False, index=True)
    
    # Action details
    action = Column(String(100), nullable=False)  # login, view_report, export, settings_change, etc.
    object_type = Column(String(100), nullable=True)  # run, report, settings, etc.
    object_id = Column(Integer, nullable=True)
    
    # Context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Additional data
    extra_data = Column(JSON, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


# =============================================================================
# COMPLIANCE EXPORT TRACKING
# =============================================================================

class ComplianceExport(Base):
    """Tracks compliance report exports for audit purposes."""
    __tablename__ = "compliance_exports"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("runs.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("auth_users.id"), nullable=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    
    # Export details
    export_format = Column(String(20), default="PDF")  # PDF, ZIP, JSON
    report_type = Column(String(50), default="COMPLIANCE")  # COMPLIANCE, AUDIT, EXECUTIVE
    
    # File info
    file_name = Column(String(255), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    
    # Frameworks included
    frameworks_included = Column(JSON, nullable=True)  # ["MITRE", "NIST", "ISO27001"]
    
    created_at = Column(DateTime, default=datetime.utcnow)


# =============================================================================
# STATIC COMPLIANCE MAPPINGS
# =============================================================================

# NIST CSF to RansomRun mapping
NIST_MAPPING = {
    "ID.AM": {"name": "Asset Management", "description": "Inventory of systems and data"},
    "ID.RA": {"name": "Risk Assessment", "description": "Identification of threats and vulnerabilities"},
    "PR.AC": {"name": "Access Control", "description": "Managing access to assets"},
    "PR.DS": {"name": "Data Security", "description": "Protecting data confidentiality and integrity"},
    "PR.IP": {"name": "Information Protection", "description": "Security policies and procedures"},
    "DE.AE": {"name": "Anomalies and Events", "description": "Detecting anomalous activity"},
    "DE.CM": {"name": "Security Monitoring", "description": "Continuous monitoring"},
    "RS.RP": {"name": "Response Planning", "description": "Incident response execution"},
    "RS.CO": {"name": "Communications", "description": "Coordination with stakeholders"},
    "RS.AN": {"name": "Analysis", "description": "Incident analysis and forensics"},
    "RS.MI": {"name": "Mitigation", "description": "Containing and eradicating threats"},
    "RC.RP": {"name": "Recovery Planning", "description": "Recovery process execution"},
    "RC.IM": {"name": "Improvements", "description": "Incorporating lessons learned"},
}

# ISO 27001 control mapping
ISO27001_MAPPING = {
    "A.5": {"name": "Information Security Policies", "description": "Management direction for information security"},
    "A.6": {"name": "Organization of Information Security", "description": "Internal organization"},
    "A.12": {"name": "Operations Security", "description": "Operational procedures and responsibilities"},
    "A.16": {"name": "Information Security Incident Management", "description": "Management of incidents"},
    "A.17": {"name": "Business Continuity", "description": "Information security aspects of BCM"},
}

# Map RansomRun events to compliance frameworks
EVENT_COMPLIANCE_MAP = {
    "RUN_STARTED": {"nist": ["DE.AE"], "iso": ["A.12"]},
    "ALERT_RECEIVED": {"nist": ["DE.AE", "DE.CM"], "iso": ["A.12", "A.16"]},
    "PLAYBOOK_TRIGGERED": {"nist": ["RS.RP"], "iso": ["A.16"]},
    "HOST_ISOLATED": {"nist": ["RS.MI"], "iso": ["A.16"]},
    "CONTAINMENT_COMPLETED": {"nist": ["RS.MI"], "iso": ["A.16"]},
    "RECOVERY_STARTED": {"nist": ["RC.RP"], "iso": ["A.17"]},
    "RECOVERY_COMPLETED": {"nist": ["RC.RP", "RC.IM"], "iso": ["A.17"]},
    "ROLLBACK_COMPLETED": {"nist": ["RC.RP"], "iso": ["A.17"]},
}
