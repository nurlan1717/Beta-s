"""CRUD operations for Directory Lab models."""

from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, func

from .models_directory import DirectoryUser, DirectoryDevice, DirectoryGroup
from .models import Host


# =============================================================================
# DIRECTORY USER CRUD
# =============================================================================

def get_directory_users(
    db: Session,
    search: str = None,
    department: str = None,
    is_privileged: bool = None,
    enabled: bool = None,
    limit: int = 100,
    offset: int = 0
) -> List[DirectoryUser]:
    """Get directory users with optional filters."""
    query = db.query(DirectoryUser)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                DirectoryUser.username.ilike(search_term),
                DirectoryUser.display_name.ilike(search_term),
                DirectoryUser.email.ilike(search_term),
                DirectoryUser.department.ilike(search_term)
            )
        )
    
    if department:
        query = query.filter(DirectoryUser.department == department)
    
    if is_privileged is not None:
        query = query.filter(DirectoryUser.is_privileged == is_privileged)
    
    if enabled is not None:
        query = query.filter(DirectoryUser.enabled == enabled)
    
    return query.order_by(DirectoryUser.username).offset(offset).limit(limit).all()


def get_directory_user(db: Session, user_id: int) -> Optional[DirectoryUser]:
    """Get a single directory user by ID."""
    return db.query(DirectoryUser).filter(DirectoryUser.id == user_id).first()


def get_directory_user_by_username(db: Session, username: str) -> Optional[DirectoryUser]:
    """Get a directory user by username."""
    return db.query(DirectoryUser).filter(DirectoryUser.username == username).first()


def create_directory_user(db: Session, **kwargs) -> DirectoryUser:
    """Create a new directory user."""
    user = DirectoryUser(**kwargs)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_directory_user(db: Session, user_id: int, **kwargs) -> Optional[DirectoryUser]:
    """Update a directory user."""
    user = get_directory_user(db, user_id)
    if not user:
        return None
    
    for key, value in kwargs.items():
        if hasattr(user, key) and value is not None:
            setattr(user, key, value)
    
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user


def delete_directory_user(db: Session, user_id: int) -> bool:
    """Delete a directory user."""
    user = get_directory_user(db, user_id)
    if not user:
        return False
    
    db.delete(user)
    db.commit()
    return True


def count_directory_users(db: Session, is_privileged: bool = None) -> int:
    """Count directory users."""
    query = db.query(func.count(DirectoryUser.id))
    if is_privileged is not None:
        query = query.filter(DirectoryUser.is_privileged == is_privileged)
    return query.scalar() or 0


# =============================================================================
# DIRECTORY DEVICE CRUD
# =============================================================================

def get_directory_devices(
    db: Session,
    search: str = None,
    device_type: str = None,
    department: str = None,
    managed_by_agent: bool = None,
    limit: int = 100,
    offset: int = 0
) -> List[DirectoryDevice]:
    """Get directory devices with optional filters."""
    query = db.query(DirectoryDevice)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                DirectoryDevice.hostname.ilike(search_term),
                DirectoryDevice.ip_address.ilike(search_term),
                DirectoryDevice.os_name.ilike(search_term),
                DirectoryDevice.department.ilike(search_term)
            )
        )
    
    if device_type:
        query = query.filter(DirectoryDevice.device_type == device_type)
    
    if department:
        query = query.filter(DirectoryDevice.department == department)
    
    if managed_by_agent is not None:
        query = query.filter(DirectoryDevice.managed_by_ransomrun_agent == managed_by_agent)
    
    return query.order_by(DirectoryDevice.hostname).offset(offset).limit(limit).all()


def get_directory_device(db: Session, device_id: int) -> Optional[DirectoryDevice]:
    """Get a single directory device by ID."""
    return db.query(DirectoryDevice).filter(DirectoryDevice.id == device_id).first()


def get_directory_device_by_hostname(db: Session, hostname: str) -> Optional[DirectoryDevice]:
    """Get a directory device by hostname."""
    return db.query(DirectoryDevice).filter(DirectoryDevice.hostname == hostname).first()


def create_directory_device(db: Session, **kwargs) -> DirectoryDevice:
    """Create a new directory device."""
    device = DirectoryDevice(**kwargs)
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def update_directory_device(db: Session, device_id: int, **kwargs) -> Optional[DirectoryDevice]:
    """Update a directory device."""
    device = get_directory_device(db, device_id)
    if not device:
        return None
    
    for key, value in kwargs.items():
        if hasattr(device, key) and value is not None:
            setattr(device, key, value)
    
    device.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(device)
    return device


def delete_directory_device(db: Session, device_id: int) -> bool:
    """Delete a directory device."""
    device = get_directory_device(db, device_id)
    if not device:
        return False
    
    db.delete(device)
    db.commit()
    return True


def count_directory_devices(db: Session, device_type: str = None, managed_by_agent: bool = None) -> int:
    """Count directory devices."""
    query = db.query(func.count(DirectoryDevice.id))
    if device_type:
        query = query.filter(DirectoryDevice.device_type == device_type)
    if managed_by_agent is not None:
        query = query.filter(DirectoryDevice.managed_by_ransomrun_agent == managed_by_agent)
    return query.scalar() or 0


def map_device_to_endpoint(db: Session, device_id: int) -> Optional[DirectoryDevice]:
    """Map a directory device to a registered endpoint by hostname."""
    device = get_directory_device(db, device_id)
    if not device:
        return None
    
    # Find matching endpoint by hostname
    endpoint = db.query(Host).filter(
        func.lower(Host.name) == func.lower(device.hostname)
    ).first()
    
    if endpoint:
        device.mapped_endpoint_id = endpoint.id
        device.managed_by_ransomrun_agent = True
        db.commit()
        db.refresh(device)
    
    return device


# =============================================================================
# DIRECTORY GROUP CRUD
# =============================================================================

def get_directory_groups(
    db: Session,
    search: str = None,
    is_privileged: bool = None,
    limit: int = 100,
    offset: int = 0
) -> List[DirectoryGroup]:
    """Get directory groups with optional filters."""
    query = db.query(DirectoryGroup)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                DirectoryGroup.name.ilike(search_term),
                DirectoryGroup.description.ilike(search_term)
            )
        )
    
    if is_privileged is not None:
        query = query.filter(DirectoryGroup.is_privileged == is_privileged)
    
    return query.order_by(DirectoryGroup.name).offset(offset).limit(limit).all()


def get_directory_group(db: Session, group_id: int) -> Optional[DirectoryGroup]:
    """Get a single directory group by ID."""
    return db.query(DirectoryGroup).filter(DirectoryGroup.id == group_id).first()


def get_directory_group_by_name(db: Session, name: str) -> Optional[DirectoryGroup]:
    """Get a directory group by name."""
    return db.query(DirectoryGroup).filter(DirectoryGroup.name == name).first()


def create_directory_group(db: Session, **kwargs) -> DirectoryGroup:
    """Create a new directory group."""
    group = DirectoryGroup(**kwargs)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def update_directory_group(db: Session, group_id: int, **kwargs) -> Optional[DirectoryGroup]:
    """Update a directory group."""
    group = get_directory_group(db, group_id)
    if not group:
        return None
    
    for key, value in kwargs.items():
        if hasattr(group, key) and value is not None:
            setattr(group, key, value)
    
    group.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(group)
    return group


def delete_directory_group(db: Session, group_id: int) -> bool:
    """Delete a directory group."""
    group = get_directory_group(db, group_id)
    if not group:
        return False
    
    db.delete(group)
    db.commit()
    return True


def count_directory_groups(db: Session, is_privileged: bool = None) -> int:
    """Count directory groups."""
    query = db.query(func.count(DirectoryGroup.id))
    if is_privileged is not None:
        query = query.filter(DirectoryGroup.is_privileged == is_privileged)
    return query.scalar() or 0


def add_user_to_group(db: Session, user_id: int, group_id: int) -> bool:
    """Add a user to a group."""
    user = get_directory_user(db, user_id)
    group = get_directory_group(db, group_id)
    
    if not user or not group:
        return False
    
    if group not in user.groups:
        user.groups.append(group)
        db.commit()
    
    return True


def remove_user_from_group(db: Session, user_id: int, group_id: int) -> bool:
    """Remove a user from a group."""
    user = get_directory_user(db, user_id)
    group = get_directory_group(db, group_id)
    
    if not user or not group:
        return False
    
    if group in user.groups:
        user.groups.remove(group)
        db.commit()
    
    return True


# =============================================================================
# STATISTICS & OVERVIEW
# =============================================================================

def get_directory_stats(db: Session) -> dict:
    """Get overall directory statistics."""
    total_users = count_directory_users(db)
    privileged_users = count_directory_users(db, is_privileged=True)
    total_devices = count_directory_devices(db)
    workstations = count_directory_devices(db, device_type="workstation")
    servers = count_directory_devices(db, device_type="server")
    domain_controllers = count_directory_devices(db, device_type="domain_controller")
    managed_devices = count_directory_devices(db, managed_by_agent=True)
    total_groups = count_directory_groups(db)
    privileged_groups = count_directory_groups(db, is_privileged=True)
    
    # Get highest risk user and device
    highest_risk_user = db.query(DirectoryUser).order_by(
        DirectoryUser.risk_score.desc()
    ).first()
    
    highest_risk_device = db.query(DirectoryDevice).order_by(
        DirectoryDevice.risk_score.desc()
    ).first()
    
    return {
        "total_users": total_users,
        "privileged_users": privileged_users,
        "total_devices": total_devices,
        "workstations": workstations,
        "servers": servers,
        "domain_controllers": domain_controllers,
        "managed_by_agent": managed_devices,
        "total_groups": total_groups,
        "privileged_groups": privileged_groups,
        "highest_risk_user": {
            "username": highest_risk_user.username if highest_risk_user else None,
            "risk_score": highest_risk_user.risk_score if highest_risk_user else 0,
            "risk_level": highest_risk_user.risk_level if highest_risk_user else "low"
        } if highest_risk_user else None,
        "highest_risk_device": {
            "hostname": highest_risk_device.hostname if highest_risk_device else None,
            "risk_score": highest_risk_device.risk_score if highest_risk_device else 0,
            "risk_level": highest_risk_device.risk_level if highest_risk_device else "low"
        } if highest_risk_device else None
    }


# =============================================================================
# SEED DEMO DATA
# =============================================================================

def seed_directory_demo_data(db: Session, force: bool = False) -> dict:
    """
    Seed demo data for directory lab.
    
    Args:
        db: Database session
        force: If True, skip check for existing data
        
    Returns:
        Dict with counts of created objects
    """
    # Check if data already exists
    if not force:
        existing_users = count_directory_users(db)
        if existing_users > 0:
            return {"message": "Demo data already exists", "created": False}
    
    created = {"users": 0, "devices": 0, "groups": 0, "memberships": 0}
    
    # Create Groups first
    groups_data = [
        {"name": "Domain Admins", "description": "Full domain administrative access", "is_privileged": True},
        {"name": "Backup Operators", "description": "Backup and restore permissions", "is_privileged": True},
        {"name": "IT Support", "description": "IT helpdesk and support staff", "is_privileged": False},
        {"name": "Finance", "description": "Finance department users", "is_privileged": False},
        {"name": "HR", "description": "Human Resources department", "is_privileged": False},
        {"name": "SOC Analysts", "description": "Security Operations Center team", "is_privileged": False},
        {"name": "Sales", "description": "Sales department users", "is_privileged": False},
        {"name": "Executives", "description": "C-level and executive staff", "is_privileged": False},
    ]
    
    groups = {}
    for g_data in groups_data:
        existing = get_directory_group_by_name(db, g_data["name"])
        if not existing:
            group = create_directory_group(db, **g_data)
            groups[g_data["name"]] = group
            created["groups"] += 1
        else:
            groups[g_data["name"]] = existing
    
    # Create Users
    users_data = [
        {
            "username": "admin.jones",
            "display_name": "Alex Jones (IT Admin)",
            "email": "alex.jones@lab.local",
            "department": "IT",
            "title": "IT Administrator",
            "is_privileged": True,
            "mfa_enabled": False,
            "risk_score": 75,
            "groups": ["Domain Admins", "IT Support"]
        },
        {
            "username": "soc.analyst1",
            "display_name": "Sarah Chen (SOC Analyst)",
            "email": "sarah.chen@lab.local",
            "department": "SOC",
            "title": "Security Analyst",
            "is_privileged": False,
            "mfa_enabled": True,
            "risk_score": 15,
            "groups": ["SOC Analysts"]
        },
        {
            "username": "soc.analyst2",
            "display_name": "Mike Rivera (SOC Analyst)",
            "email": "mike.rivera@lab.local",
            "department": "SOC",
            "title": "Senior Security Analyst",
            "is_privileged": False,
            "mfa_enabled": True,
            "risk_score": 20,
            "groups": ["SOC Analysts"]
        },
        {
            "username": "finance.manager",
            "display_name": "Jennifer Walsh (Finance Manager)",
            "email": "jennifer.walsh@lab.local",
            "department": "Finance",
            "title": "Finance Manager",
            "is_privileged": False,
            "mfa_enabled": True,
            "risk_score": 35,
            "groups": ["Finance"]
        },
        {
            "username": "finance.staff1",
            "display_name": "David Kim (Finance Analyst)",
            "email": "david.kim@lab.local",
            "department": "Finance",
            "title": "Financial Analyst",
            "is_privileged": False,
            "mfa_enabled": False,
            "risk_score": 25,
            "groups": ["Finance"]
        },
        {
            "username": "finance.staff2",
            "display_name": "Lisa Park (Accountant)",
            "email": "lisa.park@lab.local",
            "department": "Finance",
            "title": "Senior Accountant",
            "is_privileged": False,
            "mfa_enabled": True,
            "risk_score": 20,
            "groups": ["Finance"]
        },
        {
            "username": "hr.manager",
            "display_name": "Robert Thompson (HR Manager)",
            "email": "robert.thompson@lab.local",
            "department": "HR",
            "title": "HR Manager",
            "is_privileged": False,
            "mfa_enabled": True,
            "risk_score": 40,
            "groups": ["HR"]
        },
        {
            "username": "hr.staff",
            "display_name": "Emily Davis (HR Specialist)",
            "email": "emily.davis@lab.local",
            "department": "HR",
            "title": "HR Specialist",
            "is_privileged": False,
            "mfa_enabled": False,
            "risk_score": 30,
            "groups": ["HR"]
        },
        {
            "username": "sales.manager",
            "display_name": "Chris Martinez (Sales Director)",
            "email": "chris.martinez@lab.local",
            "department": "Sales",
            "title": "Sales Director",
            "is_privileged": False,
            "mfa_enabled": True,
            "risk_score": 25,
            "groups": ["Sales"]
        },
        {
            "username": "ceo.assistant",
            "display_name": "Amanda White (Executive Assistant)",
            "email": "amanda.white@lab.local",
            "department": "Executive",
            "title": "Executive Assistant to CEO",
            "is_privileged": False,
            "mfa_enabled": True,
            "risk_score": 55,
            "groups": ["Executives"]
        },
        {
            "username": "backup.operator",
            "display_name": "James Wilson (Backup Admin)",
            "email": "james.wilson@lab.local",
            "department": "IT",
            "title": "Backup Administrator",
            "is_privileged": True,
            "mfa_enabled": False,
            "risk_score": 65,
            "groups": ["Backup Operators", "IT Support"]
        },
        {
            "username": "domain.admin",
            "display_name": "System Administrator",
            "email": "sysadmin@lab.local",
            "department": "IT",
            "title": "Domain Administrator",
            "is_privileged": True,
            "mfa_enabled": False,
            "risk_score": 95,
            "groups": ["Domain Admins"]
        },
    ]
    
    users = {}
    for u_data in users_data:
        existing = get_directory_user_by_username(db, u_data["username"])
        if not existing:
            group_names = u_data.pop("groups", [])
            user = create_directory_user(db, **u_data)
            users[u_data["username"]] = user
            created["users"] += 1
            
            # Add to groups
            for group_name in group_names:
                if group_name in groups:
                    add_user_to_group(db, user.id, groups[group_name].id)
                    created["memberships"] += 1
        else:
            users[u_data["username"]] = existing
    
    # Create Devices
    devices_data = [
        {
            "hostname": "FINANCE-PC01",
            "ip_address": "192.168.10.101",
            "os_name": "Windows 11 Pro",
            "device_type": "workstation",
            "department": "Finance",
            "owner_username": "finance.manager",
            "risk_score": 30
        },
        {
            "hostname": "FINANCE-PC02",
            "ip_address": "192.168.10.102",
            "os_name": "Windows 11 Pro",
            "device_type": "workstation",
            "department": "Finance",
            "owner_username": "finance.staff1",
            "risk_score": 25
        },
        {
            "hostname": "HR-PC01",
            "ip_address": "192.168.10.110",
            "os_name": "Windows 11 Pro",
            "device_type": "workstation",
            "department": "HR",
            "owner_username": "hr.manager",
            "risk_score": 35
        },
        {
            "hostname": "SALES-PC01",
            "ip_address": "192.168.10.120",
            "os_name": "Windows 10 Pro",
            "device_type": "workstation",
            "department": "Sales",
            "owner_username": "sales.manager",
            "risk_score": 20
        },
        {
            "hostname": "CEO-PC01",
            "ip_address": "192.168.10.200",
            "os_name": "Windows 11 Pro",
            "device_type": "workstation",
            "department": "Executive",
            "owner_username": "ceo.assistant",
            "risk_score": 60
        },
        {
            "hostname": "SOC-PC01",
            "ip_address": "192.168.10.50",
            "os_name": "Windows 11 Pro",
            "device_type": "workstation",
            "department": "SOC",
            "owner_username": "soc.analyst1",
            "risk_score": 15
        },
        {
            "hostname": "FILE-SRV01",
            "ip_address": "192.168.10.10",
            "os_name": "Windows Server 2022",
            "device_type": "server",
            "department": "IT",
            "risk_score": 70
        },
        {
            "hostname": "APP-SRV01",
            "ip_address": "192.168.10.11",
            "os_name": "Windows Server 2019",
            "device_type": "server",
            "department": "IT",
            "risk_score": 55
        },
        {
            "hostname": "DB-SRV01",
            "ip_address": "192.168.10.12",
            "os_name": "Windows Server 2022",
            "device_type": "server",
            "department": "IT",
            "risk_score": 85
        },
        {
            "hostname": "BACKUP-SRV01",
            "ip_address": "192.168.10.13",
            "os_name": "Windows Server 2022",
            "device_type": "server",
            "department": "IT",
            "owner_username": "backup.operator",
            "risk_score": 80
        },
        {
            "hostname": "DC01",
            "ip_address": "192.168.10.1",
            "os_name": "Windows Server 2022",
            "device_type": "domain_controller",
            "department": "IT",
            "risk_score": 95
        },
        {
            "hostname": "JUMP01",
            "ip_address": "192.168.10.5",
            "os_name": "Windows Server 2019",
            "device_type": "jump_box",
            "department": "IT",
            "owner_username": "admin.jones",
            "risk_score": 75
        },
    ]
    
    for d_data in devices_data:
        existing = get_directory_device_by_hostname(db, d_data["hostname"])
        if not existing:
            owner_username = d_data.pop("owner_username", None)
            if owner_username and owner_username in users:
                d_data["owner_user_id"] = users[owner_username].id
            
            device = create_directory_device(db, **d_data)
            created["devices"] += 1
            
            # Try to map to existing endpoint
            map_device_to_endpoint(db, device.id)
    
    # Auto-map all devices to endpoints
    all_devices = get_directory_devices(db)
    for device in all_devices:
        if not device.mapped_endpoint_id:
            map_device_to_endpoint(db, device.id)
    
    return {
        "message": "Demo data seeded successfully",
        "created": True,
        **created
    }
