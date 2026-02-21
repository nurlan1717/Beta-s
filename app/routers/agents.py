"""Agent API endpoints for RANSOMRUN."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import (
    AgentRegisterRequest, AgentRegisterResponse,
    TaskResponse, TaskResultRequest, TaskResultResponse
)
from .. import crud

router = APIRouter(prefix="/api/agent", tags=["agent"])


@router.post("/register", response_model=AgentRegisterResponse)
def register_agent(request: AgentRegisterRequest, db: Session = Depends(get_db)):
    """
    Register or update an agent.
    Called by the Windows agent on startup.
    """
    host = crud.create_or_update_host(
        db,
        agent_id=request.agent_id,
        hostname=request.hostname,
        ip_address=request.ip_address
    )
    return AgentRegisterResponse(
        id=host.id,
        name=host.name,
        agent_id=host.agent_id,
        ip_address=host.ip_address,
        status=host.status.value
    )


@router.get("/tasks", response_model=TaskResponse)
def get_task(agent_id: str, db: Session = Depends(get_db)):
    """
    Get the next pending task for an agent.
    Called by the Windows agent in its polling loop.
    """
    # Find host by agent_id
    host = crud.get_host_by_agent_id(db, agent_id)
    if not host:
        raise HTTPException(status_code=404, detail="Agent not registered")
    
    # Update host status to ONLINE
    host.status = crud.HostStatus.ONLINE
    db.commit()
    
    # Get oldest pending task
    task = crud.get_pending_task_for_host(db, host.id)
    
    if not task:
        return TaskResponse(task_id=None)
    
    # Mark task as SENT
    crud.mark_task_sent(db, task.id)
    
    return TaskResponse(
        task_id=task.id,
        type=task.type,
        parameters=task.parameters or {}
    )


@router.post("/task-result", response_model=TaskResultResponse)
def report_task_result(request: TaskResultRequest, db: Session = Depends(get_db)):
    """
    Report the result of a completed task.
    Called by the Windows agent after executing a task.
    """
    task = crud.get_task_by_id(db, request.task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    crud.complete_task(
        db,
        task_id=request.task_id,
        status=request.status,
        result_message=request.result_message
    )
    
    # Handle isolation and recovery task results
    isolation_task_types = [
        "response_isolate_host", "response_reisolate_host", "response_deisolate_host",
        "recovery_enable_user", "recovery_restore_files_from_quarantine"
    ]
    if task.type in isolation_task_types:
        from .recovery import handle_isolation_task_result
        handle_isolation_task_result(db, task, request.status, request.result_message or "")
    
    return TaskResultResponse(
        success=True,
        message=f"Task {request.task_id} marked as {request.status}"
    )


# =============================================================================
# Host Management Endpoints
# =============================================================================

from pydantic import BaseModel
from typing import Optional

class HostUpdateRequest(BaseModel):
    name: Optional[str] = None
    notes: Optional[str] = None


@router.patch("/hosts/{host_id}")
def update_host(host_id: int, request: HostUpdateRequest, db: Session = Depends(get_db)):
    """Update host details (rename, add notes)."""
    host = crud.get_host_by_id(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    if request.name:
        host.name = request.name
    if request.notes is not None:
        host.notes = request.notes
    
    db.commit()
    db.refresh(host)
    
    return {"success": True, "message": f"Host {host_id} updated"}


@router.delete("/hosts/{host_id}")
def delete_host(host_id: int, db: Session = Depends(get_db)):
    """Remove a host from the platform and all related data."""
    from ..models import (
        Run, Task, Alert, BehaviorProfile, RunEvent, AffectedFile, 
        Metric, IOC, WhatIfScenario, RunFeedback, BusinessImpact, 
        ComplianceReport, IRSession, Host
    )
    
    # Get run IDs first before any deletions
    run_ids = [r[0] for r in db.query(Run.id).filter(Run.host_id == host_id).all()]
    
    if run_ids:
        # Delete all run-related records
        db.query(BehaviorProfile).filter(BehaviorProfile.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(WhatIfScenario).filter(WhatIfScenario.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(RunFeedback).filter(RunFeedback.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(BusinessImpact).filter(BusinessImpact.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(ComplianceReport).filter(ComplianceReport.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(IRSession).filter(IRSession.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(RunEvent).filter(RunEvent.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(AffectedFile).filter(AffectedFile.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(Metric).filter(Metric.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(IOC).filter(IOC.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(Alert).filter(Alert.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(Task).filter(Task.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(Run).filter(Run.id.in_(run_ids)).delete(synchronize_session=False)
    
    # Delete any remaining tasks for this host
    db.query(Task).filter(Task.host_id == host_id).delete(synchronize_session=False)
    
    # Delete the host directly by ID
    deleted = db.query(Host).filter(Host.id == host_id).delete(synchronize_session=False)
    
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Host not found")
    
    db.commit()
    
    return {"success": True, "message": f"Host {host_id} and all related data removed"}
