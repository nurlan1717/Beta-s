"""Playbook management API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from ..database import get_db
from ..models import Alert, Host, Playbook, ResponseExecution
from ..services.playbook_engine import PlaybookEngine
from ..deps.auth import require_user

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


@router.get("/")
def list_playbooks(db: Session = Depends(get_db), user = Depends(require_user)):
    """List all playbooks."""
    playbooks = db.query(Playbook).all()
    return [
        {
            "id": pb.id,
            "code": pb.code,
            "name": pb.name,
            "description": pb.description,
            "trigger_rule_id": pb.trigger_rule_id,
            "severity_threshold": pb.severity_threshold,
            "enabled": pb.enabled,
            "requires_approval": pb.requires_approval,
            "mitre_techniques": pb.mitre_techniques,
            "trigger_count": pb.trigger_count,
            "last_triggered_at": pb.last_triggered_at.isoformat() if pb.last_triggered_at else None,
            "action_count": len(pb.actions)
        }
        for pb in playbooks
    ]


@router.get("/{playbook_id}")
def get_playbook(playbook_id: int, db: Session = Depends(get_db), user = Depends(require_user)):
    """Get playbook details with actions."""
    playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    return {
        "id": playbook.id,
        "code": playbook.code,
        "name": playbook.name,
        "description": playbook.description,
        "trigger_rule_id": playbook.trigger_rule_id,
        "severity_threshold": playbook.severity_threshold,
        "mitre_techniques": playbook.mitre_techniques,
        "enabled": playbook.enabled,
        "requires_approval": playbook.requires_approval,
        "dry_run_only": playbook.dry_run_only,
        "created_by": playbook.created_by,
        "created_at": playbook.created_at.isoformat(),
        "trigger_count": playbook.trigger_count,
        "last_triggered_at": playbook.last_triggered_at.isoformat() if playbook.last_triggered_at else None,
        "actions": [
            {
                "id": a.id,
                "order": a.order,
                "action_type": a.action_type,
                "parameters": a.parameters,
                "requires_approval": a.requires_approval,
                "timeout_seconds": a.timeout_seconds,
                "continue_on_failure": a.continue_on_failure,
                "description": a.description
            }
            for a in playbook.actions
        ]
    }


@router.post("/apply/{alert_id}")
def apply_playbook_to_alert(
    alert_id: int,
    dry_run: bool = False,
    force: bool = False,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Apply matching playbooks to an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    host = db.query(Host).filter(Host.id == alert.host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    engine = PlaybookEngine(db)
    playbooks = engine.find_matching_playbooks(alert)
    
    if not playbooks:
        return {"success": False, "message": "No matching playbooks found", "playbooks_executed": 0}
    
    results = []
    for playbook in playbooks:
        result = engine.execute_playbook(
            playbook=playbook,
            alert=alert,
            host=host,
            dry_run=dry_run,
            force=force,
            initiated_by=user.email
        )
        results.append(result)
    
    return {
        "success": True,
        "playbooks_executed": len(results),
        "alert_id": alert_id,
        "host_id": host.id,
        "dry_run": dry_run,
        "results": results
    }


@router.post("/{playbook_id}/test")
def test_playbook(
    playbook_id: int,
    host_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Test a playbook in dry-run mode."""
    playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    # Create a test alert
    test_alert = Alert(
        host_id=host.id,
        rule_id=playbook.trigger_rule_id,
        rule_description=f"Test alert for playbook {playbook.code}",
        severity=10,
        raw={"test": True, "playbook_test": playbook.code}
    )
    db.add(test_alert)
    db.commit()
    
    engine = PlaybookEngine(db)
    result = engine.execute_playbook(
        playbook=playbook,
        alert=test_alert,
        host=host,
        dry_run=True,
        force=True,
        initiated_by=user.email
    )
    
    return {
        **result,
        "test_alert_id": test_alert.id,
        "note": "This was a test execution in dry-run mode"
    }


@router.patch("/{playbook_id}/toggle")
def toggle_playbook(
    playbook_id: int,
    enabled: bool,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Enable or disable a playbook."""
    playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    playbook.enabled = enabled
    db.commit()
    
    return {
        "success": True,
        "playbook_id": playbook_id,
        "code": playbook.code,
        "name": playbook.name,
        "enabled": enabled
    }


@router.get("/executions/{alert_id}")
def get_playbook_executions(
    alert_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get all playbook executions for an alert."""
    executions = db.query(ResponseExecution).filter(
        ResponseExecution.alert_id == alert_id
    ).order_by(ResponseExecution.created_at.desc()).all()
    
    return [
        {
            "id": ex.id,
            "playbook_id": ex.playbook_id,
            "playbook_code": ex.playbook.code if ex.playbook else None,
            "action_type": ex.action_type,
            "status": ex.status.value if hasattr(ex.status, 'value') else ex.status,
            "dry_run": ex.dry_run,
            "requires_approval": ex.requires_approval,
            "approved_by": ex.approved_by,
            "started_at": ex.started_at.isoformat() if ex.started_at else None,
            "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
            "result_message": ex.result_message,
            "error_message": ex.error_message
        }
        for ex in executions
    ]
