"""Recovery and Isolation API endpoints for RANSOMRUN."""

from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    EventType, RecoveryPlanStatus, RecoveryEventType,
    TaskStatus
)
from .. import crud

router = APIRouter(prefix="/api", tags=["recovery"])


# =============================================================================
# SCHEMAS
# =============================================================================

class IsolationRequest(BaseModel):
    policy: Optional[str] = "FIREWALL_BLOCK"  # FIREWALL_BLOCK, DISABLE_NIC, HYBRID
    adapter_name: Optional[str] = None  # For DISABLE_NIC policy


class IsolationResponse(BaseModel):
    success: bool
    message: str
    task_id: Optional[int] = None
    host_id: int
    is_isolated: bool


class RecoveryStartRequest(BaseModel):
    notes: Optional[str] = None
    include_deisolation: bool = True
    include_user_reenable: bool = True
    include_file_restore: bool = True
    quarantine_dir: Optional[str] = "C:\\RansomLab\\Quarantine"
    restore_target_dir: Optional[str] = "C:\\RansomLab\\Restored"
    username_to_reenable: Optional[str] = None


class RecoveryStartResponse(BaseModel):
    success: bool
    message: str
    recovery_plan_id: int
    tasks_created: int


class RecoveryPlanResponse(BaseModel):
    id: int
    run_id: int
    host_id: int
    status: str
    created_at: str
    completed_at: Optional[str]
    notes: Optional[str]
    events: List[dict]


class SetPolicyRequest(BaseModel):
    policy: str  # FIREWALL_BLOCK, DISABLE_NIC, HYBRID


# =============================================================================
# HOST ISOLATION ENDPOINTS
# =============================================================================

@router.post("/hosts/{host_id}/isolate", response_model=IsolationResponse)
def isolate_host(
    host_id: int,
    request: IsolationRequest = IsolationRequest(),
    db: Session = Depends(get_db)
):
    """
    Isolate a host by creating a response_isolate_host task.
    The agent will apply the isolation policy (firewall block, NIC disable, or hybrid).
    """
    host = crud.get_host_by_id(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Set isolation policy on host if provided
    policy = request.policy or host.isolation_policy or "FIREWALL_BLOCK"
    crud.set_host_isolation_policy(db, host_id, policy)
    
    # Get active run for this host (if any)
    active_run = crud.get_active_run_for_host(db, host_id)
    run_id = active_run.id if active_run else None
    
    # Create isolation task
    task_params = {
        "policy": policy,
        "action": "isolate"
    }
    if request.adapter_name:
        task_params["adapter_name"] = request.adapter_name
    
    task = crud.create_task(
        db,
        host_id=host_id,
        task_type="response_isolate_host",
        parameters=task_params,
        run_id=run_id
    )
    
    # Create run event if associated with a run
    if run_id:
        crud.create_run_event(
            db, run_id, EventType.RESPONSE_TASK_CREATED, host_id,
            {"task_type": "response_isolate_host", "policy": policy}
        )
    
    return IsolationResponse(
        success=True,
        message=f"Isolation task created for host {host.name} with policy {policy}",
        task_id=task.id,
        host_id=host_id,
        is_isolated=host.is_isolated
    )


@router.post("/hosts/{host_id}/reisolate", response_model=IsolationResponse)
def reisolate_host(
    host_id: int,
    request: IsolationRequest = IsolationRequest(),
    db: Session = Depends(get_db)
):
    """
    Re-isolate a host that may have partial isolation or suspected breach.
    Cleans up old isolation rules and re-applies fresh ones.
    """
    host = crud.get_host_by_id(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    policy = request.policy or host.isolation_policy or "FIREWALL_BLOCK"
    crud.set_host_isolation_policy(db, host_id, policy)
    
    active_run = crud.get_active_run_for_host(db, host_id)
    run_id = active_run.id if active_run else None
    
    # Create re-isolation task
    task_params = {
        "policy": policy,
        "action": "reisolate"
    }
    if request.adapter_name:
        task_params["adapter_name"] = request.adapter_name
    
    task = crud.create_task(
        db,
        host_id=host_id,
        task_type="response_reisolate_host",
        parameters=task_params,
        run_id=run_id
    )
    
    if run_id:
        crud.create_run_event(
            db, run_id, EventType.RESPONSE_TASK_CREATED, host_id,
            {"task_type": "response_reisolate_host", "policy": policy, "reason": "re-isolation"}
        )
    
    return IsolationResponse(
        success=True,
        message=f"Re-isolation task created for host {host.name}",
        task_id=task.id,
        host_id=host_id,
        is_isolated=host.is_isolated
    )


@router.post("/hosts/{host_id}/deisolate", response_model=IsolationResponse)
def deisolate_host(
    host_id: int,
    request: IsolationRequest = IsolationRequest(),
    db: Session = Depends(get_db)
):
    """
    De-isolate a host, restoring normal network connectivity.
    Removes firewall rules and/or re-enables network adapters.
    """
    host = crud.get_host_by_id(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    if not host.is_isolated:
        return IsolationResponse(
            success=True,
            message=f"Host {host.name} is not currently isolated",
            task_id=None,
            host_id=host_id,
            is_isolated=False
        )
    
    policy = host.isolation_policy or "FIREWALL_BLOCK"
    
    active_run = crud.get_active_run_for_host(db, host_id)
    run_id = active_run.id if active_run else None
    
    # Create de-isolation task
    task_params = {
        "policy": policy,
        "action": "deisolate"
    }
    if request.adapter_name:
        task_params["adapter_name"] = request.adapter_name
    
    task = crud.create_task(
        db,
        host_id=host_id,
        task_type="response_deisolate_host",
        parameters=task_params,
        run_id=run_id
    )
    
    if run_id:
        crud.create_run_event(
            db, run_id, EventType.RESPONSE_TASK_CREATED, host_id,
            {"task_type": "response_deisolate_host", "policy": policy}
        )
    
    return IsolationResponse(
        success=True,
        message=f"De-isolation task created for host {host.name}",
        task_id=task.id,
        host_id=host_id,
        is_isolated=host.is_isolated
    )


@router.post("/hosts/{host_id}/isolation-policy", response_model=dict)
def set_isolation_policy(
    host_id: int,
    request: SetPolicyRequest,
    db: Session = Depends(get_db)
):
    """Set the default isolation policy for a host."""
    host = crud.set_host_isolation_policy(db, host_id, request.policy)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    return {
        "success": True,
        "host_id": host_id,
        "isolation_policy": host.isolation_policy
    }


@router.get("/hosts/{host_id}/isolation-status")
def get_isolation_status(host_id: int, db: Session = Depends(get_db)):
    """Get the current isolation status of a host."""
    host = crud.get_host_by_id(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    return {
        "host_id": host_id,
        "host_name": host.name,
        "is_isolated": host.is_isolated,
        "isolation_policy": host.isolation_policy,
        "last_isolated_at": host.last_isolated_at.isoformat() if host.last_isolated_at else None,
        "last_deisolated_at": host.last_deisolated_at.isoformat() if host.last_deisolated_at else None
    }


# =============================================================================
# RECOVERY PLAN ENDPOINTS
# =============================================================================

@router.post("/runs/{run_id}/recovery/start", response_model=RecoveryStartResponse)
def start_recovery(
    run_id: int,
    request: RecoveryStartRequest = RecoveryStartRequest(),
    db: Session = Depends(get_db)
):
    """
    Start the recovery phase for a run.
    Creates a RecoveryPlan and generates recovery tasks based on the run state.
    """
    run = crud.get_run_by_id(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    # Check if recovery plan already exists
    existing_plan = crud.get_recovery_plan_by_run(db, run_id)
    if existing_plan:
        raise HTTPException(
            status_code=400,
            detail=f"Recovery plan already exists for this run (ID: {existing_plan.id}, Status: {existing_plan.status.value})"
        )
    
    host = run.host
    if not host:
        raise HTTPException(status_code=400, detail="Run has no associated host")
    
    # Create recovery plan
    plan = crud.create_recovery_plan(
        db,
        run_id=run_id,
        host_id=host.id,
        notes=request.notes
    )
    
    # Create RECOVERY_STARTED event
    crud.create_recovery_event(
        db, plan.id, RecoveryEventType.RECOVERY_STARTED,
        {"run_id": run_id, "host_id": host.id}
    )
    
    # Also create a run event
    crud.create_run_event(
        db, run_id, EventType.RECOVERY_STARTED, host.id,
        {"recovery_plan_id": plan.id}
    )
    
    tasks_created = 0
    
    # 1. De-isolation task (if host is isolated)
    if request.include_deisolation and host.is_isolated:
        policy = host.isolation_policy or "FIREWALL_BLOCK"
        task = crud.create_task(
            db,
            host_id=host.id,
            task_type="response_deisolate_host",
            parameters={"policy": policy, "action": "deisolate"},
            run_id=run_id
        )
        crud.create_recovery_event(
            db, plan.id, RecoveryEventType.RECOVERY_TASK_CREATED,
            {"task_id": task.id, "task_type": "response_deisolate_host"}
        )
        tasks_created += 1
    
    # 2. User re-enable task (check if user was disabled in this run)
    if request.include_user_reenable:
        # Look for disable_user tasks in this run
        disable_tasks = db.query(crud.Task).filter(
            crud.Task.run_id == run_id,
            crud.Task.type == "response_disable_user",
            crud.Task.status == TaskStatus.COMPLETED
        ).all()
        
        for disable_task in disable_tasks:
            username = disable_task.parameters.get("username") if disable_task.parameters else None
            if username:
                task = crud.create_task(
                    db,
                    host_id=host.id,
                    task_type="recovery_enable_user",
                    parameters={"username": username},
                    run_id=run_id
                )
                crud.create_recovery_event(
                    db, plan.id, RecoveryEventType.RECOVERY_TASK_CREATED,
                    {"task_id": task.id, "task_type": "recovery_enable_user", "username": username}
                )
                tasks_created += 1
        
        # Also check if a specific username was provided
        if request.username_to_reenable and not any(
            t.parameters.get("username") == request.username_to_reenable 
            for t in disable_tasks if t.parameters
        ):
            task = crud.create_task(
                db,
                host_id=host.id,
                task_type="recovery_enable_user",
                parameters={"username": request.username_to_reenable},
                run_id=run_id
            )
            crud.create_recovery_event(
                db, plan.id, RecoveryEventType.RECOVERY_TASK_CREATED,
                {"task_id": task.id, "task_type": "recovery_enable_user", "username": request.username_to_reenable}
            )
            tasks_created += 1
    
    # 3. File restore task (if quarantine was used)
    if request.include_file_restore:
        # Check if scenario used quarantine mode
        scenario_config = run.scenario.config if run.scenario and run.scenario.config else {}
        if scenario_config.get("quarantine_mode", False) or request.quarantine_dir:
            task = crud.create_task(
                db,
                host_id=host.id,
                task_type="recovery_restore_files_from_quarantine",
                parameters={
                    "quarantine_dir": request.quarantine_dir or "C:\\RansomLab\\Quarantine",
                    "restore_target_dir": request.restore_target_dir or "C:\\RansomLab\\Restored"
                },
                run_id=run_id
            )
            crud.create_recovery_event(
                db, plan.id, RecoveryEventType.RECOVERY_TASK_CREATED,
                {"task_id": task.id, "task_type": "recovery_restore_files_from_quarantine"}
            )
            tasks_created += 1
    
    # Update plan status to IN_PROGRESS if tasks were created
    if tasks_created > 0:
        crud.update_recovery_plan_status(db, plan.id, RecoveryPlanStatus.IN_PROGRESS)
    
    return RecoveryStartResponse(
        success=True,
        message=f"Recovery plan created with {tasks_created} tasks",
        recovery_plan_id=plan.id,
        tasks_created=tasks_created
    )


@router.get("/runs/{run_id}/recovery", response_model=Optional[RecoveryPlanResponse])
def get_recovery_plan(run_id: int, db: Session = Depends(get_db)):
    """Get the recovery plan for a run."""
    plan = crud.get_recovery_plan_by_run(db, run_id)
    if not plan:
        return None
    
    events = crud.get_recovery_events_by_plan(db, plan.id)
    
    return RecoveryPlanResponse(
        id=plan.id,
        run_id=plan.run_id,
        host_id=plan.host_id,
        status=plan.status.value,
        created_at=plan.created_at.isoformat() if plan.created_at else None,
        completed_at=plan.completed_at.isoformat() if plan.completed_at else None,
        notes=plan.notes,
        events=[
            {
                "id": e.id,
                "event_type": e.event_type.value,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "details": e.details
            }
            for e in events
        ]
    )


@router.get("/runs/{run_id}/containment")
def get_containment_status(run_id: int, db: Session = Depends(get_db)):
    """Get containment status and tasks for a run."""
    run = crud.get_run_by_id(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    host = run.host
    containment_tasks = crud.get_containment_tasks_by_run(db, run_id)
    
    # Find first successful isolation
    first_isolation = None
    for task in containment_tasks:
        if task.type in ["response_isolate_host", "response_reisolate_host"] and task.status == TaskStatus.COMPLETED:
            first_isolation = task.completed_at
            break
    
    return {
        "run_id": run_id,
        "host_id": host.id if host else None,
        "host_name": host.name if host else None,
        "is_isolated": host.is_isolated if host else False,
        "isolation_policy": host.isolation_policy if host else None,
        "first_containment_at": first_isolation.isoformat() if first_isolation else None,
        "containment_tasks": [
            {
                "id": t.id,
                "type": t.type,
                "status": t.status.value,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                "result_message": t.result_message
            }
            for t in containment_tasks
        ]
    }


@router.post("/runs/{run_id}/recovery/check-completion")
def check_recovery_completion(run_id: int, db: Session = Depends(get_db)):
    """
    Check if recovery is complete and update plan status.
    Also updates business impact and compliance report if recovery completed.
    """
    plan = crud.get_recovery_plan_by_run(db, run_id)
    if not plan:
        raise HTTPException(status_code=404, detail="No recovery plan found for this run")
    
    completed = crud.check_recovery_plan_completion(db, plan.id)
    
    if completed and plan.status == RecoveryPlanStatus.COMPLETED:
        # Calculate actual recovery hours
        if plan.created_at and plan.completed_at:
            delta = plan.completed_at - plan.created_at
            actual_hours = delta.total_seconds() / 3600
            
            # Update business impact
            crud.update_business_impact_actuals(db, run_id, actual_hours)
            
            # Update compliance report
            host = crud.get_host_by_id(db, plan.host_id)
            containment_tasks = crud.get_containment_tasks_by_run(db, run_id)
            recovery_tasks = crud.get_recovery_tasks_by_run(db, run_id)
            
            containment_summary = "; ".join([
                f"{t.type}: {t.status.value}" for t in containment_tasks
            ])
            recovery_summary = "; ".join([
                f"{t.type}: {t.status.value}" for t in recovery_tasks
            ])
            
            crud.update_compliance_report_recovery(
                db, run_id,
                deisolation_time=host.last_deisolated_at if host else None,
                recovery_completed_time=plan.completed_at,
                containment_summary=containment_summary,
                recovery_summary=recovery_summary
            )
    
    # Refresh plan
    plan = crud.get_recovery_plan_by_run(db, run_id)
    
    return {
        "recovery_plan_id": plan.id,
        "status": plan.status.value,
        "completed": plan.status in [RecoveryPlanStatus.COMPLETED, RecoveryPlanStatus.FAILED],
        "completed_at": plan.completed_at.isoformat() if plan.completed_at else None
    }


# =============================================================================
# TASK RESULT HANDLER EXTENSION
# =============================================================================

def handle_isolation_task_result(db: Session, task, status: str, result_message: str):
    """
    Handle task result for isolation-related tasks.
    Updates host isolation status and creates recovery events.
    Called from the main task-result endpoint.
    """
    if not task.host_id:
        return
    
    host = crud.get_host_by_id(db, task.host_id)
    if not host:
        return
    
    if status == "completed":
        if task.type == "response_isolate_host":
            crud.update_host_isolation(db, host.id, True, task.parameters.get("policy"))
            if task.run_id:
                crud.create_run_event(
                    db, task.run_id, EventType.HOST_ISOLATED, host.id,
                    {"policy": task.parameters.get("policy"), "message": result_message}
                )
        
        elif task.type == "response_reisolate_host":
            crud.update_host_isolation(db, host.id, True, task.parameters.get("policy"))
            if task.run_id:
                crud.create_run_event(
                    db, task.run_id, EventType.HOST_REISOLATED, host.id,
                    {"policy": task.parameters.get("policy"), "message": result_message}
                )
        
        elif task.type == "response_deisolate_host":
            crud.update_host_isolation(db, host.id, False)
            if task.run_id:
                crud.create_run_event(
                    db, task.run_id, EventType.HOST_DEISOLATED, host.id,
                    {"message": result_message}
                )
                
                # Update recovery event if plan exists
                plan = crud.get_recovery_plan_by_run(db, task.run_id)
                if plan:
                    crud.create_recovery_event(
                        db, plan.id, RecoveryEventType.HOST_DEISOLATED,
                        {"task_id": task.id, "message": result_message}
                    )
        
        elif task.type == "recovery_enable_user":
            if task.run_id:
                plan = crud.get_recovery_plan_by_run(db, task.run_id)
                if plan:
                    crud.create_recovery_event(
                        db, plan.id, RecoveryEventType.USER_REENABLED,
                        {"task_id": task.id, "username": task.parameters.get("username"), "message": result_message}
                    )
        
        elif task.type == "recovery_restore_files_from_quarantine":
            if task.run_id:
                plan = crud.get_recovery_plan_by_run(db, task.run_id)
                if plan:
                    crud.create_recovery_event(
                        db, plan.id, RecoveryEventType.FILES_RESTORED_FROM_QUARANTINE,
                        {"task_id": task.id, "message": result_message}
                    )
    
    # Check recovery plan completion
    if task.run_id and task.type in ["response_deisolate_host", "recovery_enable_user", "recovery_restore_files_from_quarantine"]:
        plan = crud.get_recovery_plan_by_run(db, task.run_id)
        if plan:
            crud.check_recovery_plan_completion(db, plan.id)
