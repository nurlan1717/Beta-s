"""Wazuh alerts API endpoints for RANSOMRUN."""

from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import WazuhAlertRequest, AlertResponse
from .. import crud

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.post("/wazuh", response_model=AlertResponse)
def receive_wazuh_alert(request: WazuhAlertRequest, db: Session = Depends(get_db)):
    """
    Receive an alert from Wazuh SIEM.
    Creates alert record and triggers playbook actions if configured.
    """
    # Extract alert data
    rule_id = request.rule.id
    rule_description = request.rule.description
    severity = request.rule.level or 0
    agent_name = request.agent.name if request.agent else None
    
    # Parse timestamp
    try:
        if request.timestamp:
            timestamp = datetime.fromisoformat(request.timestamp.replace("Z", "+00:00"))
        else:
            timestamp = datetime.utcnow()
    except:
        timestamp = datetime.utcnow()
    
    # Find host by agent name
    host = None
    host_id = None
    if agent_name:
        host = crud.get_host_by_name(db, agent_name)
        if not host:
            # Try matching by agent_id as fallback
            host = crud.get_host_by_agent_id(db, agent_name)
        if host:
            host_id = host.id
    
    # Find active run for this host
    run_id = None
    if host_id:
        active_run = crud.get_active_run_for_host(db, host_id)
        if active_run:
            run_id = active_run.id
    
    # Create alert record
    alert = crud.create_alert(
        db,
        rule_id=rule_id,
        rule_description=rule_description,
        agent_name=agent_name,
        severity=severity,
        timestamp=timestamp,
        raw=request.model_dump(),
        host_id=host_id,
        run_id=run_id
    )
    
    # Look up playbook for this rule_id
    tasks_created = 0
    if host_id:
        playbook = crud.get_playbook_by_rule_id(db, rule_id)
        if playbook and playbook.actions:
            for action in playbook.actions:
                action_type = action.get("type")
                action_params = action.get("parameters", {})
                
                if action_type:
                    crud.create_task(
                        db,
                        host_id=host_id,
                        task_type=action_type,
                        parameters=action_params,
                        run_id=run_id
                    )
                    tasks_created += 1
    
    return AlertResponse(
        success=True,
        alert_id=alert.id,
        tasks_created=tasks_created
    )


@router.get("/")
def list_alerts(limit: int = 100, db: Session = Depends(get_db)):
    """Get recent alerts."""
    alerts = crud.get_all_alerts(db, limit=limit)
    return [
        {
            "id": a.id,
            "rule_id": a.rule_id,
            "rule_description": a.rule_description,
            "agent_name": a.agent_name,
            "severity": a.severity,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "host_id": a.host_id,
            "run_id": a.run_id
        }
        for a in alerts
    ]
