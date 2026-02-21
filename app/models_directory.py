"""Directory Lab Models - Simulated AD/Directory for ransomware simulation context.

This module provides models for a simulated Active Directory environment
used for demo, training, and ransomware simulation reporting.

NOT for production AD control - this is a "Directory Lab" module only.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Table,
    Enum as SQLEnum
)
from sqlalchemy.orm import relationship
from enum import Enum

from .models import Base


# =============================================================================
# ENUMS
# =============================================================================

class DeviceType(str, Enum):
    WORKSTATION = "workstation"
    SERVER = "server"
    DOMAIN_CONTROLLER = "domain_controller"
    JUMP_BOX = "jump_box"


class Department(str, Enum):
    IT = "IT"
    SOC = "SOC"
    FINANCE = "Finance"
    HR = "HR"
    SALES = "Sales"
    EXECUTIVE = "Executive"
    OPERATIONS = "Operations"


# =============================================================================
# ASSOCIATION TABLES (Many-to-Many)
# =============================================================================

# User <-> Group association
directory_user_groups = Table(
    'directory_user_groups',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('directory_users.id', ondelete='CASCADE'), primary_key=True),
    Column('group_id', Integer, ForeignKey('directory_groups.id', ondelete='CASCADE'), primary_key=True)
)

# Device <-> Group association (optional)
directory_device_groups = Table(
    'directory_device_groups',
    Base.metadata,
    Column('device_id', Integer, ForeignKey('directory_devices.id', ondelete='CASCADE'), primary_key=True),
    Column('group_id', Integer, ForeignKey('directory_groups.id', ondelete='CASCADE'), primary_key=True)
)


# =============================================================================
# DIRECTORY USER MODEL
# =============================================================================

class DirectoryUser(Base):
    """Simulated AD user for directory lab."""
    __tablename__ = "directory_users"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(200), nullable=False)
    email = Column(String(200), nullable=True)
    department = Column(String(50), nullable=True)
    title = Column(String(100), nullable=True)
    
    # Status flags
    enabled = Column(Boolean, default=True)
    is_privileged = Column(Boolean, default=False, index=True)
    mfa_enabled = Column(Boolean, default=False)
    
    # Activity tracking
    last_logon = Column(DateTime, nullable=True)
    password_last_set = Column(DateTime, nullable=True)
    
    # Risk assessment
    risk_score = Column(Integer, default=10)  # 0-100
    
    # Notes
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    groups = relationship(
        "DirectoryGroup",
        secondary=directory_user_groups,
        back_populates="members"
    )
    owned_devices = relationship("DirectoryDevice", back_populates="owner")
    
    def __repr__(self):
        return f"<DirectoryUser {self.username}>"
    
    @property
    def risk_level(self):
        """Return risk level string based on score."""
        if self.risk_score >= 81:
            return "critical"
        elif self.risk_score >= 51:
            return "high"
        elif self.risk_score >= 21:
            return "medium"
        return "low"


# =============================================================================
# DIRECTORY DEVICE MODEL
# =============================================================================

class DirectoryDevice(Base):
    """Simulated AD device/computer for directory lab."""
    __tablename__ = "directory_devices"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    os_name = Column(String(100), nullable=True)
    device_type = Column(String(30), default="workstation")  # workstation/server/domain_controller/jump_box
    department = Column(String(50), nullable=True)
    
    # Owner relationship
    owner_user_id = Column(Integer, ForeignKey('directory_users.id', ondelete='SET NULL'), nullable=True)
    
    # Integration with RansomRun agents
    managed_by_ransomrun_agent = Column(Boolean, default=False)
    mapped_endpoint_id = Column(Integer, ForeignKey('hosts.id', ondelete='SET NULL'), nullable=True)
    
    # Activity tracking
    last_seen = Column(DateTime, nullable=True)
    
    # Risk assessment
    risk_score = Column(Integer, default=10)  # 0-100
    
    # Notes
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = relationship("DirectoryUser", back_populates="owned_devices")
    groups = relationship(
        "DirectoryGroup",
        secondary=directory_device_groups,
        back_populates="devices"
    )
    
    def __repr__(self):
        return f"<DirectoryDevice {self.hostname}>"
    
    @property
    def risk_level(self):
        """Return risk level string based on score."""
        if self.risk_score >= 81:
            return "critical"
        elif self.risk_score >= 51:
            return "high"
        elif self.risk_score >= 21:
            return "medium"
        return "low"
    
    @property
    def device_type_display(self):
        """Return formatted device type for display."""
        type_map = {
            "workstation": "Workstation",
            "server": "Server",
            "domain_controller": "Domain Controller",
            "jump_box": "Jump Box"
        }
        return type_map.get(self.device_type, self.device_type)


# =============================================================================
# DIRECTORY GROUP MODEL
# =============================================================================

class DirectoryGroup(Base):
    """Simulated AD group for directory lab."""
    __tablename__ = "directory_groups"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_privileged = Column(Boolean, default=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    members = relationship(
        "DirectoryUser",
        secondary=directory_user_groups,
        back_populates="groups"
    )
    devices = relationship(
        "DirectoryDevice",
        secondary=directory_device_groups,
        back_populates="groups"
    )
    
    def __repr__(self):
        return f"<DirectoryGroup {self.name}>"
    
    @property
    def member_count(self):
        return len(self.members)
    
    @property
    def device_count(self):
        return len(self.devices)
