"""Simulation runs API endpoints for RANSOMRUN."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import RunSimulationRequest, RunSimulationResponse
from .. import crud

router = APIRouter(prefix="/api", tags=["runs"])


@router.post("/run-simulation", response_model=RunSimulationResponse)
def start_simulation(request: RunSimulationRequest, db: Session = Depends(get_db)):
    """
    Start a new ransomware simulation run.
    Creates a Run and initial simulation Task.
    """
    # Validate host exists
    host = crud.get_host_by_id(db, request.host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Validate scenario exists
    scenario = crud.get_scenario_by_id(db, request.scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # Check if host already has an active run
    active_run = crud.get_active_run_for_host(db, host.id)
    if active_run:
        raise HTTPException(
            status_code=400, 
            detail=f"Host already has an active run (ID: {active_run.id})"
        )
    
    # Create new run
    run = crud.create_run(db, host_id=host.id, scenario_id=scenario.id)
    
    # Create initial simulation task with scenario config
    task_params = {
        "scenario_key": scenario.key,
        "run_id": run.id,
        "scenario_config": scenario.config or {}
    }
    
    crud.create_task(
        db,
        host_id=host.id,
        task_type="simulate_ransomware",
        parameters=task_params,
        run_id=run.id
    )
    
    # Create run event
    from ..models import EventType
    crud.create_run_event(db, run.id, EventType.RUN_CREATED, host.id, {
        "scenario_key": scenario.key,
        "scenario_name": scenario.name
    })
    
    return RunSimulationResponse(
        success=True,
        run_id=run.id,
        message=f"Simulation started for {host.name} with scenario '{scenario.name}'"
    )


@router.get("/runs")
def list_runs(db: Session = Depends(get_db)):
    """Get all simulation runs."""
    runs = crud.get_all_runs(db)
    return [
        {
            "id": r.id,
            "host_id": r.host_id,
            "host_name": r.host.name if r.host else None,
            "scenario_id": r.scenario_id,
            "scenario_name": r.scenario.name if r.scenario else None,
            "status": r.status.value,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "ended_at": r.ended_at.isoformat() if r.ended_at else None
        }
        for r in runs
    ]


@router.get("/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db)):
    """Get details of a specific run with extended forensic data."""
    run = crud.get_run_by_id(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    tasks = crud.get_tasks_by_run(db, run_id)
    alerts = crud.get_alerts_by_run(db, run_id)
    events = crud.get_events_by_run(db, run_id)
    metrics = crud.get_metrics_by_run(db, run_id)
    iocs = crud.get_iocs_by_run(db, run_id)
    affected_files = crud.get_affected_files_by_run(db, run_id)
    
    from ..models import MITRE_MAPPING
    
    return {
        "id": run.id,
        "host": {
            "id": run.host.id,
            "name": run.host.name,
            "agent_id": run.host.agent_id
        } if run.host else None,
        "scenario": {
            "id": run.scenario.id,
            "key": run.scenario.key,
            "name": run.scenario.name,
            "description": run.scenario.description,
            "category": run.scenario.category.value if run.scenario.category else None,
            "config": run.scenario.config
        } if run.scenario else None,
        "status": run.status.value,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "ended_at": run.ended_at.isoformat() if run.ended_at else None,
        "notes": run.notes,
        "tasks": [
            {
                "id": t.id,
                "type": t.type,
                "parameters": t.parameters,
                "status": t.status.value,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                "result_message": t.result_message
            }
            for t in tasks
        ],
        "alerts": [
            {
                "id": a.id,
                "rule_id": a.rule_id,
                "rule_description": a.rule_description,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "mitre": MITRE_MAPPING.get(a.rule_id, {})
            }
            for a in alerts
        ],
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type.value,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "details": e.details
            }
            for e in events
        ],
        "metrics": {m.name: m.value for m in metrics},
        "iocs": [
            {
                "id": i.id,
                "type": i.ioc_type.value,
                "value": i.value,
                "context": i.context
            }
            for i in iocs
        ],
        "affected_files_count": len(affected_files),
        "affected_files": [
            {
                "original_path": f.original_path,
                "new_path": f.new_path,
                "action_type": f.action_type.value
            }
            for f in affected_files[:50]  # Limit to 50
        ]
    }


@router.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    """Get all registered hosts."""
    hosts = crud.get_all_hosts(db)
    return [
        {
            "id": h.id,
            "name": h.name,
            "agent_id": h.agent_id,
            "ip_address": h.ip_address,
            "status": h.status.value,
            "created_at": h.created_at.isoformat() if h.created_at else None,
            "updated_at": h.updated_at.isoformat() if h.updated_at else None
        }
        for h in hosts
    ]


@router.get("/hosts/{host_id}")
def get_host(host_id: int, db: Session = Depends(get_db)):
    """Get details of a specific host."""
    host = crud.get_host_by_id(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    runs = crud.get_runs_by_host(db, host_id)
    alerts = crud.get_alerts_by_host(db, host_id)
    
    return {
        "id": host.id,
        "name": host.name,
        "agent_id": host.agent_id,
        "ip_address": host.ip_address,
        "status": host.status.value,
        "created_at": host.created_at.isoformat() if host.created_at else None,
        "updated_at": host.updated_at.isoformat() if host.updated_at else None,
        "runs": [
            {
                "id": r.id,
                "scenario_name": r.scenario.name if r.scenario else None,
                "status": r.status.value,
                "started_at": r.started_at.isoformat() if r.started_at else None
            }
            for r in runs[:10]  # Last 10 runs
        ],
        "recent_alerts": [
            {
                "id": a.id,
                "rule_id": a.rule_id,
                "rule_description": a.rule_description,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None
            }
            for a in alerts[:10]  # Last 10 alerts
        ]
    }


@router.get("/scenarios")
def list_scenarios(db: Session = Depends(get_db)):
    """Get all available scenarios."""
    scenarios = crud.get_all_scenarios(db)
    return [
        {
            "id": s.id,
            "key": s.key,
            "name": s.name,
            "description": s.description
        }
        for s in scenarios
    ]


@router.get("/playbooks")
def list_playbooks(db: Session = Depends(get_db)):
    """Get all playbooks."""
    playbooks = crud.get_all_playbooks(db)
    return [
        {
            "id": p.id,
            "name": p.name,
            "rule_id": p.rule_id,
            "actions": p.actions,
            "enabled": p.enabled
        }
        for p in playbooks
    ]


@router.post("/runs/{run_id}/stop")
def stop_simulation(run_id: int, db: Session = Depends(get_db)):
    """
    Stop a running or pending simulation.
    
    Behavior:
    - PENDING: Immediately cancel and remove pending tasks
    - RUNNING: Create stop task for agent, mark as STOPPING
    - STOPPING: Return current state (idempotent)
    - COMPLETED/FAILED/CANCELED: Return 409 error
    """
    result = crud.stop_run(db, run_id)
    
    if not result["success"]:
        # Return 409 Conflict for non-stoppable runs
        if "not stoppable" in result["message"]:
            raise HTTPException(status_code=409, detail=result["message"])
        # Return 404 for not found
        if "not found" in result["message"]:
            raise HTTPException(status_code=404, detail=result["message"])
        # Other errors
        raise HTTPException(status_code=400, detail=result["message"])
    
    return {
        "success": True,
        "run_id": run_id,
        "status": result.get("status"),
        "message": result["message"]
    }


@router.delete("/runs/{run_id}")
def delete_simulation(
    run_id: int, 
    force: bool = False,
    db: Session = Depends(get_db)
):
    """
    Delete a simulation run and all related data.
    
    Safety:
    - Blocks deletion of RUNNING/STOPPING runs unless force=true
    - If force=true, attempts to stop the run first
    
    Deletes:
    - Tasks, Alerts, Events, Metrics, IOCs, Affected Files
    - Recovery Plans, Behavior Profiles, What-If Scenarios
    - IR Sessions, Run Feedback, Business Impact, Compliance Reports
    """
    result = crud.delete_run(db, run_id, force=force)
    
    if not result["success"]:
        # Return 409 Conflict for RUNNING/STOPPING without force
        if "without force" in result["message"]:
            raise HTTPException(status_code=409, detail=result["message"])
        # Return 404 for not found
        if "not found" in result["message"]:
            raise HTTPException(status_code=404, detail=result["message"])
        # Other errors
        raise HTTPException(status_code=400, detail=result["message"])
    
    return result
