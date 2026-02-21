"""SOAR (Security Orchestration, Automation and Response) API endpoints.

Provides robust host isolation and network restoration capabilities:
- POST /api/soar/isolate/{host_id}  - Isolate a host from the network
- POST /api/soar/restore-network/{host_id}  - Restore network connectivity
- GET  /api/soar/isolation-state/{host_id}  - Get current isolation state
- GET  /api/soar/action-logs/{host_id}  - Get action logs for a host

Isolation modes:
- adapter: Disable network adapters (reliable, obvious)
- firewall: Block all traffic except backend communication (stealthy)
- hybrid: Both adapter disable + firewall rules (maximum isolation)
"""

import os
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import (
    Host, Task, TaskStatus, Run, Alert, RunEvent, EventType,
    HostIsolationState, ResponseActionLog, IsolationMode
)
from ..deps.auth import require_user

router = APIRouter(prefix="/api/soar", tags=["soar"])


# =============================================================================
# CONFIGURATION
# =============================================================================

# Default backend configuration - can be overridden via environment
# IMPORTANT: This is the IP where the RansomRun web server is running
# The agent must be able to reach this IP after isolation
DEFAULT_BACKEND_IP = os.environ.get("RANSOMRUN_BACKEND_IP", "192.168.10.55")
DEFAULT_BACKEND_PORTS = [8000, 443, 9200, 5044]  # Backend, HTTPS, Elasticsearch, Logstash


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class IsolateHostRequest(BaseModel):
    """Request body for host isolation."""
    mode: str = Field(default="firewall", description="Isolation mode: adapter, firewall, or hybrid")
    allow_backend: bool = Field(default=True, description="Allow communication with backend")
    backend_ip: Optional[str] = Field(default=None, description="Backend IP (auto-detected if not provided)")
    backend_ports: Optional[List[int]] = Field(default=None, description="Backend ports to allow")
    dry_run: bool = Field(default=False, description="Simulate without making changes")
    run_id: Optional[int] = Field(default=None, description="Associated run ID")
    alert_id: Optional[int] = Field(default=None, description="Associated alert ID")


class RestoreNetworkRequest(BaseModel):
    """Request body for network restoration."""
    dry_run: bool = Field(default=False, description="Simulate without making changes")
    force: bool = Field(default=False, description="Force restore even if not marked as isolated")


class IsolationStateResponse(BaseModel):
    """Response for isolation state query."""
    host_id: int
    is_isolated: bool
    isolation_mode: Optional[str]
    isolated_at: Optional[str]
    backend_ip: Optional[str]
    backend_ports: Optional[List[int]]
    pre_state_available: bool
    last_action_status: Optional[str]
    last_action_message: Optional[str]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_host_or_404(db: Session, host_id: int) -> Host:
    """Get host by ID or raise 404."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail=f"Host with ID {host_id} not found")
    return host


def _get_active_isolation_state(db: Session, host_id: int) -> Optional[HostIsolationState]:
    """Get the active isolation state for a host."""
    return db.query(HostIsolationState).filter(
        HostIsolationState.host_id == host_id,
        HostIsolationState.active == True
    ).order_by(desc(HostIsolationState.created_at)).first()


def _detect_backend_ip(request) -> str:
    """Try to detect the backend IP from the request."""
    # Try to get from X-Forwarded-For or client host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    # Fallback to configured default
    return DEFAULT_BACKEND_IP


def _create_isolation_task(
    db: Session,
    host: Host,
    task_type: str,
    parameters: dict,
    run_id: Optional[int] = None
) -> Task:
    """Create an agent task for isolation/restore."""
    task = Task(
        host_id=host.id,
        run_id=run_id,
        type=task_type,
        parameters=parameters,
        status=TaskStatus.PENDING
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _create_action_log(
    db: Session,
    host_id: int,
    action: str,
    params: dict,
    dry_run: bool = False,
    run_id: Optional[int] = None,
    alert_id: Optional[int] = None,
    isolation_state_id: Optional[int] = None
) -> ResponseActionLog:
    """Create a response action log entry."""
    log = ResponseActionLog(
        host_id=host_id,
        run_id=run_id,
        alert_id=alert_id,
        isolation_state_id=isolation_state_id,
        action=action,
        action_params=params,
        dry_run=dry_run,
        status="pending",
        created_at=datetime.utcnow()
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


# =============================================================================
# API ENDPOINTS
# =============================================================================

@router.post("/isolate/{host_id}")
def isolate_host(
    host_id: int,
    request: IsolateHostRequest,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Isolate a host from the network.
    
    Creates an agent task that will:
    1. Capture the current network state (adapters, IPs, DNS, gateway)
    2. Apply isolation based on the selected mode
    3. Verify isolation succeeded
    4. Store state for later restoration
    
    Modes:
    - adapter: Disable network adapters (except virtual/loopback)
    - firewall: Block all traffic except backend communication
    - hybrid: Both adapter disable + firewall rules
    """
    host = _get_host_or_404(db, host_id)
    
    # Validate mode
    try:
        isolation_mode = IsolationMode(request.mode)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid isolation mode: {request.mode}. Valid modes: adapter, firewall, hybrid"
        )
    
    # Check if already isolated
    existing_state = _get_active_isolation_state(db, host_id)
    if existing_state and not request.dry_run:
        return {
            "success": False,
            "message": f"Host {host.name} is already isolated (mode: {existing_state.mode.value})",
            "already_isolated": True,
            "isolation_state_id": existing_state.id,
            "isolated_at": existing_state.isolated_at.isoformat() if existing_state.isolated_at else None
        }
    
    # Determine backend IP
    backend_ip = request.backend_ip or DEFAULT_BACKEND_IP
    backend_ports = request.backend_ports or DEFAULT_BACKEND_PORTS
    
    # Create isolation state record
    isolation_state = HostIsolationState(
        host_id=host_id,
        run_id=request.run_id,
        alert_id=request.alert_id,
        mode=isolation_mode,
        active=False,  # Will be set to True by agent upon success
        backend_ip=backend_ip,
        backend_ports=backend_ports,
        triggered_by="manual",
        initiated_by_user=user.email if hasattr(user, 'email') else str(user.id)
    )
    
    if not request.dry_run:
        db.add(isolation_state)
        db.commit()
        db.refresh(isolation_state)
    
    # Build task parameters
    task_params = {
        "task_type": "soar_isolate_host",
        "host_id": host_id,
        "mode": request.mode,
        "allow_backend": request.allow_backend,
        "backend_allow": {
            "ip": backend_ip,
            "ports": backend_ports
        },
        "capture_state": True,
        "dry_run": request.dry_run,
        "isolation_state_id": isolation_state.id if not request.dry_run else None
    }
    
    # Create action log
    action_log = _create_action_log(
        db, host_id, "isolate_host", task_params, request.dry_run,
        request.run_id, request.alert_id,
        isolation_state.id if not request.dry_run else None
    )
    
    # Create agent task
    if not request.dry_run:
        task = _create_isolation_task(db, host, "soar_isolate_host", task_params, request.run_id)
        
        # Update host isolation status
        host.is_isolated = True
        host.quarantine_status = "ISOLATING"
        db.commit()
        
        return {
            "success": True,
            "message": f"Isolation task created for host {host.name}",
            "task_id": task.id,
            "isolation_state_id": isolation_state.id,
            "action_log_id": action_log.id,
            "mode": request.mode,
            "backend_ip": backend_ip,
            "backend_ports": backend_ports,
            "dry_run": False
        }
    else:
        return {
            "success": True,
            "message": f"[DRY RUN] Would isolate host {host.name} with mode: {request.mode}",
            "task_id": None,
            "isolation_state_id": None,
            "action_log_id": action_log.id,
            "mode": request.mode,
            "backend_ip": backend_ip,
            "backend_ports": backend_ports,
            "dry_run": True,
            "planned_actions": [
                "Capture current network state (adapters, IPs, DNS, gateway)",
                f"Apply {request.mode} isolation",
                f"Allow backend communication to {backend_ip}:{backend_ports}" if request.allow_backend else "Block all traffic",
                "Verify isolation succeeded",
                "Store state locally for recovery after reboot"
            ]
        }


@router.post("/restore-network/{host_id}")
def restore_network(
    host_id: int,
    request: RestoreNetworkRequest,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Restore network connectivity for an isolated host.
    
    Creates an agent task that will:
    1. Load the pre-isolation state from backend or local file
    2. Restore network adapters to their original state
    3. Remove isolation firewall rules
    4. Restore DNS and gateway settings if changed
    5. Verify restoration succeeded
    """
    host = _get_host_or_404(db, host_id)
    
    # Get active isolation state
    isolation_state = _get_active_isolation_state(db, host_id)
    
    if not isolation_state and not request.force:
        # Check if host thinks it's isolated but has no state
        if host.is_isolated:
            # Create a dummy state for forced restore
            pass
        else:
            return {
                "success": False,
                "message": f"Host {host.name} is not currently isolated (no active isolation state found)",
                "not_isolated": True,
                "hint": "Use force=true to attempt restore anyway"
            }
    
    # Build task parameters
    task_params = {
        "task_type": "soar_restore_network",
        "host_id": host_id,
        "isolation_state_id": isolation_state.id if isolation_state else None,
        "pre_state": isolation_state.pre_state_json if isolation_state else None,
        "mode": isolation_state.mode.value if isolation_state else "unknown",
        "dry_run": request.dry_run,
        "force": request.force
    }
    
    # Create action log
    action_log = _create_action_log(
        db, host_id, "restore_network", task_params, request.dry_run,
        isolation_state.run_id if isolation_state else None,
        isolation_state.alert_id if isolation_state else None,
        isolation_state.id if isolation_state else None
    )
    
    if not request.dry_run:
        # Create agent task
        task = _create_isolation_task(
            db, host, "soar_restore_network", task_params,
            isolation_state.run_id if isolation_state else None
        )
        
        # Update host status
        host.quarantine_status = "RESTORING"
        db.commit()
        
        return {
            "success": True,
            "message": f"Network restore task created for host {host.name}",
            "task_id": task.id,
            "action_log_id": action_log.id,
            "isolation_state_id": isolation_state.id if isolation_state else None,
            "mode": isolation_state.mode.value if isolation_state else "unknown",
            "dry_run": False
        }
    else:
        return {
            "success": True,
            "message": f"[DRY RUN] Would restore network for host {host.name}",
            "task_id": None,
            "action_log_id": action_log.id,
            "isolation_state_id": isolation_state.id if isolation_state else None,
            "mode": isolation_state.mode.value if isolation_state else "unknown",
            "dry_run": True,
            "planned_actions": [
                "Load pre-isolation state from backend or local file",
                "Re-enable disabled network adapters",
                "Remove isolation firewall rules",
                "Restore DNS and gateway settings",
                "Verify network connectivity restored"
            ]
        }


@router.get("/isolation-state/{host_id}")
def get_isolation_state(
    host_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Get the current isolation state for a host.
    
    Returns detailed information about:
    - Whether the host is isolated
    - Isolation mode used
    - Pre-isolation network state (if captured)
    - Backend allow configuration
    - Last action status
    """
    host = _get_host_or_404(db, host_id)
    
    # Get active isolation state
    isolation_state = _get_active_isolation_state(db, host_id)
    
    # Get last action log
    last_action = db.query(ResponseActionLog).filter(
        ResponseActionLog.host_id == host_id,
        ResponseActionLog.action.in_(["isolate_host", "restore_network"])
    ).order_by(desc(ResponseActionLog.created_at)).first()
    
    # Get historical isolation states
    history = db.query(HostIsolationState).filter(
        HostIsolationState.host_id == host_id
    ).order_by(desc(HostIsolationState.created_at)).limit(10).all()
    
    return {
        "host_id": host_id,
        "host_name": host.name,
        "is_isolated": host.is_isolated,
        "quarantine_status": host.quarantine_status,
        
        "active_isolation": {
            "id": isolation_state.id,
            "mode": isolation_state.mode.value,
            "isolated_at": isolation_state.isolated_at.isoformat() if isolation_state.isolated_at else None,
            "backend_ip": isolation_state.backend_ip,
            "backend_ports": isolation_state.backend_ports,
            "pre_state_available": isolation_state.pre_state_json is not None,
            "triggered_by": isolation_state.triggered_by,
            "initiated_by": isolation_state.initiated_by_user
        } if isolation_state else None,
        
        "last_action": {
            "id": last_action.id,
            "action": last_action.action,
            "status": last_action.status,
            "success": last_action.success,
            "message": last_action.message,
            "dry_run": last_action.dry_run,
            "timestamp": last_action.created_at.isoformat() if last_action.created_at else None,
            "duration_seconds": last_action.duration_seconds,
            "verification_passed": last_action.verification_passed
        } if last_action else None,
        
        "history": [
            {
                "id": s.id,
                "mode": s.mode.value,
                "active": s.active,
                "isolated_at": s.isolated_at.isoformat() if s.isolated_at else None,
                "restored_at": s.restored_at.isoformat() if s.restored_at else None
            }
            for s in history
        ]
    }


@router.get("/action-logs/{host_id}")
def get_action_logs(
    host_id: int,
    limit: int = Query(default=20, le=100),
    action_filter: Optional[str] = Query(default=None, description="Filter by action type"),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Get response action logs for a host.
    
    Returns detailed logs including:
    - Commands executed
    - stdout/stderr output
    - Pre/post state snapshots
    - Verification results
    """
    host = _get_host_or_404(db, host_id)
    
    query = db.query(ResponseActionLog).filter(ResponseActionLog.host_id == host_id)
    
    if action_filter:
        query = query.filter(ResponseActionLog.action == action_filter)
    
    logs = query.order_by(desc(ResponseActionLog.created_at)).limit(limit).all()
    
    return {
        "host_id": host_id,
        "host_name": host.name,
        "total_logs": len(logs),
        "logs": [
            {
                "id": log.id,
                "action": log.action,
                "status": log.status,
                "success": log.success,
                "message": log.message,
                "dry_run": log.dry_run,
                "started_at": log.started_at.isoformat() if log.started_at else None,
                "ended_at": log.ended_at.isoformat() if log.ended_at else None,
                "duration_seconds": log.duration_seconds,
                "commands_executed": log.commands_executed,
                "stdout": log.stdout[:2000] if log.stdout else None,  # Truncate for response
                "stderr": log.stderr[:2000] if log.stderr else None,
                "verification_passed": log.verification_passed,
                "verification_details": log.verification_details,
                "errors": log.errors,
                "created_at": log.created_at.isoformat() if log.created_at else None
            }
            for log in logs
        ]
    }


@router.post("/action-logs/{log_id}/result")
def update_action_log_result(
    log_id: int,
    result: dict,
    db: Session = Depends(get_db)
):
    """
    Update an action log with results from the agent.
    Called by the agent after executing an isolation/restore task.
    """
    log = db.query(ResponseActionLog).filter(ResponseActionLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Action log not found")
    
    # Update log with results
    log.status = result.get("status", "completed")
    log.success = result.get("success", False)
    log.message = result.get("message", "")
    log.ended_at = datetime.utcnow()
    log.duration_seconds = result.get("duration_seconds")
    log.commands_executed = result.get("commands")
    log.stdout = result.get("stdout", "")
    log.stderr = result.get("stderr", "")
    log.pre_state = result.get("pre_state")
    log.post_state = result.get("post_state")
    log.verification_passed = result.get("verification_passed")
    log.verification_details = result.get("verification_details")
    log.errors = result.get("errors", [])
    log.agent_version = result.get("agent_version")
    
    # If this was an isolation and it succeeded, update the isolation state
    if log.action == "isolate_host" and log.success and log.isolation_state_id:
        isolation_state = db.query(HostIsolationState).filter(
            HostIsolationState.id == log.isolation_state_id
        ).first()
        if isolation_state:
            isolation_state.active = True
            isolation_state.isolated_at = datetime.utcnow()
            isolation_state.pre_state_json = result.get("pre_state")
            isolation_state.post_isolation_state_json = result.get("post_state")
            isolation_state.firewall_rules = result.get("firewall_rules")
            
            # Update host
            host = db.query(Host).filter(Host.id == log.host_id).first()
            if host:
                host.is_isolated = True
                host.quarantine_status = "QUARANTINED"
                host.last_isolated_at = datetime.utcnow()
    
    # If this was a restore and it succeeded, update the isolation state
    if log.action == "restore_network" and log.success and log.isolation_state_id:
        isolation_state = db.query(HostIsolationState).filter(
            HostIsolationState.id == log.isolation_state_id
        ).first()
        if isolation_state:
            isolation_state.active = False
            isolation_state.restored_at = datetime.utcnow()
            isolation_state.post_restore_state_json = result.get("post_state")
            
            # Update host
            host = db.query(Host).filter(Host.id == log.host_id).first()
            if host:
                host.is_isolated = False
                host.quarantine_status = "CLEAN"
                host.last_deisolated_at = datetime.utcnow()
    
    db.commit()
    
    return {"success": True, "message": "Action log updated", "log_id": log_id}


@router.get("/policies")
def list_isolation_policies(user = Depends(require_user)):
    """List available isolation modes with descriptions."""
    return {
        "modes": [
            {
                "value": "adapter",
                "name": "Adapter Disable",
                "description": "Disable network adapters (except virtual/loopback). Most reliable but obvious to user.",
                "pros": ["Very reliable", "Works offline", "Survives reboot with state file"],
                "cons": ["Obvious to user", "May break agent communication if not careful"]
            },
            {
                "value": "firewall",
                "name": "Firewall Lockdown",
                "description": "Block all traffic via Windows Firewall except backend communication. Less obvious.",
                "pros": ["Less obvious", "Agent can still communicate", "Reversible"],
                "cons": ["Can be bypassed by disabling firewall", "May conflict with other firewall rules"]
            },
            {
                "value": "hybrid",
                "name": "Hybrid (Both)",
                "description": "Apply both firewall rules AND disable adapters. Maximum isolation.",
                "pros": ["Maximum isolation", "Defense in depth"],
                "cons": ["Most complex to restore", "May cause issues with virtual adapters"]
            }
        ],
        "default": "firewall",
        "recommended_for_lab": "firewall"
    }
