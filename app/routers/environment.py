"""API endpoints for Directory Lab / Environment Management.

This module provides REST API endpoints for managing simulated AD objects
including users, devices, and groups for ransomware simulation context.
"""

from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db
from ..models_directory import DirectoryUser, DirectoryDevice, DirectoryGroup
from .. import crud_directory as crud

# Try to import auth dependency
try:
    from .ui import get_current_user, require_user
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False
    def require_user():
        return None

router = APIRouter(prefix="/api/environment", tags=["environment"])


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

class UserCreate(BaseModel):
    username: str
    display_name: str
    email: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    enabled: bool = True
    is_privileged: bool = False
    mfa_enabled: bool = False
    risk_score: int = 10
    notes: Optional[str] = None


class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    enabled: Optional[bool] = None
    is_privileged: Optional[bool] = None
    mfa_enabled: Optional[bool] = None
    risk_score: Optional[int] = None
    notes: Optional[str] = None


class DeviceCreate(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    device_type: str = "workstation"
    department: Optional[str] = None
    owner_user_id: Optional[int] = None
    risk_score: int = 10
    notes: Optional[str] = None


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_name: Optional[str] = None
    device_type: Optional[str] = None
    department: Optional[str] = None
    owner_user_id: Optional[int] = None
    risk_score: Optional[int] = None
    notes: Optional[str] = None


class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_privileged: bool = False


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_privileged: Optional[bool] = None


class GroupMembership(BaseModel):
    user_id: int
    group_id: int


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def serialize_user(user: DirectoryUser) -> dict:
    """Serialize a DirectoryUser to dict."""
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "department": user.department,
        "title": user.title,
        "enabled": user.enabled,
        "is_privileged": user.is_privileged,
        "mfa_enabled": user.mfa_enabled,
        "last_logon": user.last_logon.isoformat() if user.last_logon else None,
        "password_last_set": user.password_last_set.isoformat() if user.password_last_set else None,
        "risk_score": user.risk_score,
        "risk_level": user.risk_level,
        "notes": user.notes,
        "groups": [{"id": g.id, "name": g.name, "is_privileged": g.is_privileged} for g in user.groups],
        "owned_devices_count": len(user.owned_devices),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None
    }


def serialize_device(device: DirectoryDevice) -> dict:
    """Serialize a DirectoryDevice to dict."""
    return {
        "id": device.id,
        "hostname": device.hostname,
        "ip_address": device.ip_address,
        "os_name": device.os_name,
        "device_type": device.device_type,
        "device_type_display": device.device_type_display,
        "department": device.department,
        "owner_user_id": device.owner_user_id,
        "owner": {
            "id": device.owner.id,
            "username": device.owner.username,
            "display_name": device.owner.display_name
        } if device.owner else None,
        "managed_by_ransomrun_agent": device.managed_by_ransomrun_agent,
        "mapped_endpoint_id": device.mapped_endpoint_id,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "risk_score": device.risk_score,
        "risk_level": device.risk_level,
        "notes": device.notes,
        "groups": [{"id": g.id, "name": g.name} for g in device.groups],
        "created_at": device.created_at.isoformat() if device.created_at else None,
        "updated_at": device.updated_at.isoformat() if device.updated_at else None
    }


def serialize_group(group: DirectoryGroup) -> dict:
    """Serialize a DirectoryGroup to dict."""
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "is_privileged": group.is_privileged,
        "member_count": group.member_count,
        "device_count": group.device_count,
        "members": [{"id": m.id, "username": m.username, "display_name": m.display_name} for m in group.members],
        "created_at": group.created_at.isoformat() if group.created_at else None,
        "updated_at": group.updated_at.isoformat() if group.updated_at else None
    }


def check_admin_role(user) -> bool:
    """Check if user has admin role."""
    if not user:
        return True  # No auth = allow (dev mode)
    if hasattr(user, 'role'):
        return user.role in ['ADMIN', 'admin', 'Admin']
    return True


# =============================================================================
# STATISTICS ENDPOINT
# =============================================================================

@router.get("/stats")
def get_environment_stats(db: Session = Depends(get_db)):
    """Get overall environment/directory statistics."""
    stats = crud.get_directory_stats(db)
    return {"success": True, **stats}


# =============================================================================
# USER ENDPOINTS
# =============================================================================

@router.get("/users")
def list_users(
    search: Optional[str] = Query(None),
    department: Optional[str] = Query(None),
    is_privileged: Optional[bool] = Query(None),
    enabled: Optional[bool] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db)
):
    """List directory users with optional filters."""
    users = crud.get_directory_users(
        db, search=search, department=department,
        is_privileged=is_privileged, enabled=enabled,
        limit=limit, offset=offset
    )
    return {
        "success": True,
        "count": len(users),
        "users": [serialize_user(u) for u in users]
    }


@router.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    """Get a single directory user by ID."""
    user = crud.get_directory_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"success": True, "user": serialize_user(user)}


@router.post("/users")
def create_user(
    data: UserCreate,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Create a new directory user."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    # Check for duplicate username
    existing = crud.get_directory_user_by_username(db, data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    user = crud.create_directory_user(db, **data.dict())
    return {"success": True, "user": serialize_user(user)}


@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    data: UserUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Update a directory user."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    user = crud.update_directory_user(db, user_id, **data.dict(exclude_unset=True))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"success": True, "user": serialize_user(user)}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Delete a directory user."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    success = crud.delete_directory_user(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"success": True, "message": "User deleted"}


# =============================================================================
# DEVICE ENDPOINTS
# =============================================================================

@router.get("/devices")
def list_devices(
    search: Optional[str] = Query(None),
    device_type: Optional[str] = Query(None),
    department: Optional[str] = Query(None),
    managed_by_agent: Optional[bool] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db)
):
    """List directory devices with optional filters."""
    devices = crud.get_directory_devices(
        db, search=search, device_type=device_type,
        department=department, managed_by_agent=managed_by_agent,
        limit=limit, offset=offset
    )
    return {
        "success": True,
        "count": len(devices),
        "devices": [serialize_device(d) for d in devices]
    }


@router.get("/devices/{device_id}")
def get_device(device_id: int, db: Session = Depends(get_db)):
    """Get a single directory device by ID."""
    device = crud.get_directory_device(db, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"success": True, "device": serialize_device(device)}


@router.post("/devices")
def create_device(
    data: DeviceCreate,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Create a new directory device."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    # Check for duplicate hostname
    existing = crud.get_directory_device_by_hostname(db, data.hostname)
    if existing:
        raise HTTPException(status_code=400, detail="Hostname already exists")
    
    device = crud.create_directory_device(db, **data.dict())
    # Try to map to endpoint
    crud.map_device_to_endpoint(db, device.id)
    return {"success": True, "device": serialize_device(device)}


@router.put("/devices/{device_id}")
def update_device(
    device_id: int,
    data: DeviceUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Update a directory device."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    device = crud.update_directory_device(db, device_id, **data.dict(exclude_unset=True))
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"success": True, "device": serialize_device(device)}


@router.delete("/devices/{device_id}")
def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Delete a directory device."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    success = crud.delete_directory_device(db, device_id)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"success": True, "message": "Device deleted"}


@router.post("/devices/{device_id}/map-endpoint")
def map_device_to_endpoint(
    device_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Map a device to a RansomRun endpoint by hostname."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    device = crud.map_device_to_endpoint(db, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return {
        "success": True,
        "mapped": device.mapped_endpoint_id is not None,
        "endpoint_id": device.mapped_endpoint_id,
        "device": serialize_device(device)
    }


# =============================================================================
# GROUP ENDPOINTS
# =============================================================================

@router.get("/groups")
def list_groups(
    search: Optional[str] = Query(None),
    is_privileged: Optional[bool] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db)
):
    """List directory groups with optional filters."""
    groups = crud.get_directory_groups(
        db, search=search, is_privileged=is_privileged,
        limit=limit, offset=offset
    )
    return {
        "success": True,
        "count": len(groups),
        "groups": [serialize_group(g) for g in groups]
    }


@router.get("/groups/{group_id}")
def get_group(group_id: int, db: Session = Depends(get_db)):
    """Get a single directory group by ID."""
    group = crud.get_directory_group(db, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return {"success": True, "group": serialize_group(group)}


@router.post("/groups")
def create_group(
    data: GroupCreate,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Create a new directory group."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    # Check for duplicate name
    existing = crud.get_directory_group_by_name(db, data.name)
    if existing:
        raise HTTPException(status_code=400, detail="Group name already exists")
    
    group = crud.create_directory_group(db, **data.dict())
    return {"success": True, "group": serialize_group(group)}


@router.put("/groups/{group_id}")
def update_group(
    group_id: int,
    data: GroupUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Update a directory group."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    group = crud.update_directory_group(db, group_id, **data.dict(exclude_unset=True))
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return {"success": True, "group": serialize_group(group)}


@router.delete("/groups/{group_id}")
def delete_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Delete a directory group."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    success = crud.delete_directory_group(db, group_id)
    if not success:
        raise HTTPException(status_code=404, detail="Group not found")
    return {"success": True, "message": "Group deleted"}


# =============================================================================
# GROUP MEMBERSHIP ENDPOINTS
# =============================================================================

@router.post("/groups/{group_id}/members/{user_id}")
def add_user_to_group(
    group_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Add a user to a group."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    success = crud.add_user_to_group(db, user_id, group_id)
    if not success:
        raise HTTPException(status_code=404, detail="User or group not found")
    return {"success": True, "message": "User added to group"}


@router.delete("/groups/{group_id}/members/{user_id}")
def remove_user_from_group(
    group_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Remove a user from a group."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    success = crud.remove_user_from_group(db, user_id, group_id)
    if not success:
        raise HTTPException(status_code=404, detail="User or group not found")
    return {"success": True, "message": "User removed from group"}


# =============================================================================
# SEED DATA ENDPOINT
# =============================================================================

@router.post("/seed")
def seed_demo_data(
    force: bool = Query(False, description="Force re-seed even if data exists"),
    db: Session = Depends(get_db),
    current_user = Depends(require_user) if AUTH_AVAILABLE else None
):
    """Seed demo data for directory lab (admin only)."""
    if not check_admin_role(current_user):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    result = crud.seed_directory_demo_data(db, force=force)
    return {"success": True, **result}
