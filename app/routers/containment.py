"""Containment & Isolation API endpoints for RansomRun.

This module provides endpoints for post-simulation containment actions:
- Block ransomware paths
- Quarantine files
- Isolate/restore host network
- Retrieve ransomware artifact data

These endpoints become available when a run is COMPLETED or FAILED.
"""

import os
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Run, RunEvent, Task, EventType, RunStatus, TaskStatus
from .. import crud

router = APIRouter(prefix="/api/runs", tags=["containment"])

# Configuration flag - can be overridden via environment variable
ALLOW_CONTAINMENT_ACTIONS = os.environ.get("ALLOW_CONTAINMENT_ACTIONS", "true").lower() == "true"


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class IsolateHostRequest(BaseModel):
    method: str = "firewall_lockdown"  # "disable_adapters" | "firewall_lockdown"
    dry_run: bool = True


class RestoreNetworkRequest(BaseModel):
    dry_run: bool = True


class BlockPathRequest(BaseModel):
    path: str
    mode: str = "acl_deny"  # "acl_deny" | "quarantine_and_deny"
    dry_run: bool = True
    force: bool = False


class QuarantineRequest(BaseModel):
    path: str
    dry_run: bool = True


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _check_containment_allowed():
    """Check if containment actions are allowed."""
    if not ALLOW_CONTAINMENT_ACTIONS:
        raise HTTPException(
            status_code=403,
            detail="Containment actions are disabled. Set ALLOW_CONTAINMENT_ACTIONS=true to enable."
        )


def _get_finished_run(db: Session, run_id: int) -> Run:
    """Get a run and verify it's finished (COMPLETED or FAILED)."""
    run = crud.get_run_by_id(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    if run.status not in [RunStatus.COMPLETED, RunStatus.FAILED]:
        raise HTTPException(
            status_code=400,
            detail=f"Containment only available for finished runs. Current status: {run.status.value}"
        )
    
    return run


def _get_ransomware_artifacts(db: Session, run_id: int) -> dict:
    """Extract ransomware artifact data from run events and metrics."""
    events = crud.get_events_by_run(db, run_id)
    metrics = crud.get_metrics_by_run(db, run_id)
    iocs = crud.get_iocs_by_run(db, run_id)
    
    # Look for ransomware artifacts event
    artifacts = {
        "entry_path": None,
        "dropped_payload_path": None,
        "working_dir": None,
        "target_dir": None,
        "ransom_note_path": None,
        "encryption_key_path": None,
        "process": None
    }
    
    for event in events:
        if event.event_type == EventType.RANSOMWARE_ARTIFACTS_RECEIVED:
            details = event.details or {}
            ransomware_data = details.get("ransomware", {})
            artifacts.update({
                "entry_path": ransomware_data.get("entry_path"),
                "dropped_payload_path": ransomware_data.get("dropped_payload_path"),
                "working_dir": ransomware_data.get("working_dir"),
                "target_dir": ransomware_data.get("target_dir"),
                "ransom_note_path": ransomware_data.get("ransom_note_path"),
                "encryption_key_path": ransomware_data.get("encryption_key_path"),
                "process": ransomware_data.get("process")
            })
            break
    
    # Fallback: try to extract from IOCs if no artifacts event
    if not artifacts["entry_path"]:
        for ioc in iocs:
            if ioc.context and "entry" in ioc.context.lower():
                artifacts["entry_path"] = ioc.value
                break
    
    # Get target directory from scenario config if not set
    run = crud.get_run_by_id(db, run_id)
    if run and run.scenario and run.scenario.config:
        config = run.scenario.config
        dirs = config.get("directories_to_target", [])
        if dirs and not artifacts["target_dir"]:
            artifacts["target_dir"] = dirs[0] if isinstance(dirs, list) else dirs
    
    return artifacts


def _get_containment_status(db: Session, run_id: int, host_id: int) -> dict:
    """Get current containment status from events."""
    events = crud.get_events_by_run(db, run_id)
    
    status = {
        "isolated": False,
        "isolation_method": None,
        "isolated_at": None,
        "blocked_paths": [],
        "quarantined_files": []
    }
    
    for event in events:
        if event.event_type == EventType.HOST_ISOLATED:
            status["isolated"] = True
            status["isolation_method"] = (event.details or {}).get("method")
            status["isolated_at"] = event.timestamp.isoformat() if event.timestamp else None
        elif event.event_type == EventType.HOST_NETWORK_RESTORED:
            status["isolated"] = False
            status["isolation_method"] = None
            status["isolated_at"] = None
        elif event.event_type == EventType.PATH_BLOCKED:
            path = (event.details or {}).get("path")
            if path and path not in status["blocked_paths"]:
                status["blocked_paths"].append(path)
        elif event.event_type == EventType.FILE_QUARANTINED:
            path = (event.details or {}).get("path")
            if path and path not in status["quarantined_files"]:
                status["quarantined_files"].append(path)
    
    return status


def _create_containment_task(
    db: Session,
    run: Run,
    task_type: str,
    parameters: dict
) -> Task:
    """Create a containment task for the agent."""
    task = Task(
        run_id=run.id,
        host_id=run.host_id,
        type=task_type,
        parameters=parameters,
        status=TaskStatus.PENDING
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


# =============================================================================
# API ENDPOINTS
# =============================================================================

@router.get("/{run_id}/containment")
def get_containment_info(run_id: int, db: Session = Depends(get_db)):
    """
    Get containment information for a finished run.
    
    Returns:
    - Ransomware artifact paths (entry, payload, target, etc.)
    - Current containment status (isolated, blocked paths, etc.)
    - Host information
    """
    run = _get_finished_run(db, run_id)
    
    artifacts = _get_ransomware_artifacts(db, run_id)
    status = _get_containment_status(db, run_id, run.host_id)
    
    # Get recent containment events
    events = crud.get_events_by_run(db, run_id)
    containment_events = []
    containment_types = [
        EventType.HOST_ISOLATION_REQUESTED, EventType.HOST_ISOLATED,
        EventType.HOST_RESTORE_REQUESTED, EventType.HOST_NETWORK_RESTORED,
        EventType.PATH_BLOCK_REQUESTED, EventType.PATH_BLOCKED,
        EventType.QUARANTINE_REQUESTED, EventType.FILE_QUARANTINED,
        EventType.RANSOMWARE_ARTIFACTS_RECEIVED
    ]
    
    for event in events:
        if event.event_type in containment_types:
            containment_events.append({
                "id": event.id,
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "details": event.details
            })
    
    return {
        "run_id": run_id,
        "host": {
            "id": run.host.id,
            "name": run.host.name,
            "agent_id": run.host.agent_id,
            "ip_address": run.host.ip_address
        } if run.host else None,
        "run_status": run.status.value,
        "artifacts": artifacts,
        "containment_status": status,
        "containment_events": containment_events[-10:],  # Last 10
        "containment_allowed": ALLOW_CONTAINMENT_ACTIONS
    }


@router.post("/{run_id}/containment/isolate")
def isolate_host(run_id: int, request: IsolateHostRequest, db: Session = Depends(get_db)):
    """
    Isolate the host from the network.
    
    Methods:
    - disable_adapters: Disable network adapters (fast, obvious)
    - firewall_lockdown: Block all traffic except backend communication
    
    Creates an agent task and logs timeline events.
    """
    _check_containment_allowed()
    run = _get_finished_run(db, run_id)
    
    # Check if already isolated
    status = _get_containment_status(db, run_id, run.host_id)
    if status["isolated"] and not request.dry_run:
        return {
            "success": True,
            "message": "Host already isolated",
            "already_isolated": True,
            "method": status["isolation_method"]
        }
    
    # Validate method
    if request.method not in ["disable_adapters", "firewall_lockdown"]:
        raise HTTPException(status_code=400, detail="Invalid isolation method")
    
    # Get backend IP/port - try to auto-detect from request or use env vars
    # Default to common lab setup
    backend_ip = os.environ.get("BACKEND_IP", "192.168.10.55")
    backend_port = int(os.environ.get("BACKEND_PORT", "8000"))
    
    # Create task for agent with explicit parameters
    task_params = {
        "run_id": run_id,
        "method": request.method,
        "dry_run": request.dry_run,
        "force": False,
        "backend_ip": backend_ip,
        "backend_port": backend_port
    }
    
    task = _create_containment_task(db, run, "containment_isolate_host", task_params)
    
    # Log event with full details
    crud.create_run_event(db, run_id, EventType.HOST_ISOLATION_REQUESTED, run.host_id, {
        "method": request.method,
        "dry_run": request.dry_run,
        "task_id": task.id,
        "backend_ip": backend_ip,
        "backend_port": backend_port
    })
    
    return {
        "success": True,
        "message": f"Host isolation {'(DRY RUN - no changes will be made) ' if request.dry_run else ''}requested. Task ID: {task.id}",
        "task_id": task.id,
        "method": request.method,
        "dry_run": request.dry_run,
        "backend_ip": backend_ip,
        "backend_port": backend_port
    }


@router.post("/{run_id}/containment/restore-network")
def restore_network(run_id: int, request: RestoreNetworkRequest, db: Session = Depends(get_db)):
    """
    Restore host network connectivity.
    
    Reverses the isolation method that was used.
    """
    _check_containment_allowed()
    run = _get_finished_run(db, run_id)
    
    # Check if isolated
    status = _get_containment_status(db, run_id, run.host_id)
    if not status["isolated"] and not request.dry_run:
        return {
            "success": True,
            "message": "Host not isolated",
            "already_restored": True
        }
    
    # Create task for agent
    task_params = {
        "run_id": run_id,
        "dry_run": request.dry_run
    }
    
    task = _create_containment_task(db, run, "containment_restore_network", task_params)
    
    # Log event
    crud.create_run_event(db, run_id, EventType.HOST_RESTORE_REQUESTED, run.host_id, {
        "dry_run": request.dry_run,
        "task_id": task.id
    })
    
    return {
        "success": True,
        "message": f"Network restore {'(dry run) ' if request.dry_run else ''}requested",
        "task_id": task.id,
        "dry_run": request.dry_run
    }


@router.post("/{run_id}/containment/block-path")
def block_path(run_id: int, request: BlockPathRequest, db: Session = Depends(get_db)):
    """
    Block a file/directory path to prevent execution/access.
    
    Modes:
    - acl_deny: Use Windows ACLs to deny read/execute
    - quarantine_and_deny: Move to quarantine folder and apply ACL
    """
    _check_containment_allowed()
    run = _get_finished_run(db, run_id)
    
    if not request.path:
        raise HTTPException(status_code=400, detail="Path is required")
    
    # Check if path already blocked
    status = _get_containment_status(db, run_id, run.host_id)
    if request.path in status["blocked_paths"] and not request.force and not request.dry_run:
        return {
            "success": True,
            "message": "Path already blocked",
            "already_blocked": True,
            "path": request.path
        }
    
    # Validate mode
    if request.mode not in ["acl_deny", "quarantine_and_deny"]:
        raise HTTPException(status_code=400, detail="Invalid block mode")
    
    # Create task for agent
    task_params = {
        "run_id": run_id,
        "path": request.path,
        "mode": request.mode,
        "dry_run": request.dry_run
    }
    
    task = _create_containment_task(db, run, "containment_block_path", task_params)
    
    # Log event
    crud.create_run_event(db, run_id, EventType.PATH_BLOCK_REQUESTED, run.host_id, {
        "path": request.path,
        "mode": request.mode,
        "dry_run": request.dry_run,
        "task_id": task.id
    })
    
    return {
        "success": True,
        "message": f"Path block {'(dry run) ' if request.dry_run else ''}requested",
        "task_id": task.id,
        "path": request.path,
        "mode": request.mode,
        "dry_run": request.dry_run
    }


@router.post("/{run_id}/containment/quarantine")
def quarantine_file(run_id: int, request: QuarantineRequest, db: Session = Depends(get_db)):
    """
    Quarantine a file by moving it to a secure location.
    """
    _check_containment_allowed()
    run = _get_finished_run(db, run_id)
    
    if not request.path:
        raise HTTPException(status_code=400, detail="Path is required")
    
    # Create task for agent
    task_params = {
        "run_id": run_id,
        "path": request.path,
        "dry_run": request.dry_run
    }
    
    task = _create_containment_task(db, run, "containment_quarantine_file", task_params)
    
    # Log event
    crud.create_run_event(db, run_id, EventType.QUARANTINE_REQUESTED, run.host_id, {
        "path": request.path,
        "dry_run": request.dry_run,
        "task_id": task.id
    })
    
    return {
        "success": True,
        "message": f"Quarantine {'(dry run) ' if request.dry_run else ''}requested",
        "task_id": task.id,
        "path": request.path,
        "dry_run": request.dry_run
    }


@router.post("/{run_id}/containment/report-artifacts")
def report_artifacts(run_id: int, data: dict, db: Session = Depends(get_db)):
    """
    Receive ransomware artifact data from agent.
    
    Called by agent when simulation finishes to report:
    - Entry path, dropped payload, working dir
    - Target dir, ransom note path, encryption key path
    - Process info (pid, name, command line, sha256)
    """
    run = crud.get_run_by_id(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    ransomware_data = data.get("ransomware", {})
    host_name = data.get("host", "")
    
    # Log event with artifact data
    crud.create_run_event(db, run_id, EventType.RANSOMWARE_ARTIFACTS_RECEIVED, run.host_id, {
        "host": host_name,
        "ransomware": ransomware_data
    })
    
    return {
        "success": True,
        "message": "Ransomware artifacts recorded",
        "run_id": run_id
    }
