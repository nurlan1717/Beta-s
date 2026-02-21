"""Isolation management API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from ..database import get_db
from ..models import Host, IsolationPolicy, IsolationEvent
from ..services.isolation_engine import IsolationEngine
from ..deps.auth import require_user

router = APIRouter(prefix="/api/isolation", tags=["isolation"])


@router.post("/isolate/{host_id}")
def isolate_host(
    host_id: int,
    policy: str = "HYBRID",
    ttl_minutes: Optional[int] = None,
    dry_run: bool = False,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Isolate a host with specified policy."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    engine = IsolationEngine(db)
    result = engine.isolate_host(
        host=host,
        policy=policy,
        ttl_minutes=ttl_minutes,
        dry_run=dry_run,
        triggered_by="manual",
        initiated_by_user=user.email
    )
    
    return result


@router.post("/deisolate/{host_id}")
def deisolate_host(
    host_id: int,
    dry_run: bool = False,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """De-isolate a host (escape hatch)."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    engine = IsolationEngine(db)
    result = engine.deisolate_host(
        host=host,
        dry_run=dry_run,
        triggered_by="manual",
        initiated_by_user=user.email
    )
    
    return result


@router.get("/status/{host_id}")
def get_isolation_status(
    host_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get isolation status for a host."""
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    engine = IsolationEngine(db)
    status = engine.get_isolation_status(host)
    
    return status


@router.get("/policies")
def list_isolation_policies(user = Depends(require_user)):
    """List available isolation policies."""
    policies = [
        {
            "value": policy.value,
            "name": policy.name,
            "description": _get_policy_description(policy.value)
        }
        for policy in IsolationPolicy
    ]
    
    return {"policies": policies}


@router.get("/events/{host_id}")
def get_isolation_events(
    host_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get isolation event history for a host."""
    events = db.query(IsolationEvent).filter(
        IsolationEvent.host_id == host_id
    ).order_by(IsolationEvent.timestamp.desc()).limit(limit).all()
    
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "isolation_policy": e.isolation_policy,
            "ttl_minutes": e.ttl_minutes,
            "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            "triggered_by": e.triggered_by,
            "alert_id": e.alert_id,
            "playbook_id": e.playbook_id,
            "initiated_by_user": e.initiated_by_user,
            "dry_run": e.dry_run,
            "success": e.success,
            "error_message": e.error_message,
            "timestamp": e.timestamp.isoformat()
        }
        for e in events
    ]


@router.post("/check-ttl")
def check_ttl_expirations(
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Check for expired isolation TTLs and auto-unisolate."""
    engine = IsolationEngine(db)
    result = engine.check_ttl_expirations()
    return result


def _get_policy_description(policy: str) -> str:
    """Get human-readable description for isolation policy."""
    descriptions = {
        "NONE": "No isolation",
        "FIREWALL_BLOCK": "Block all inbound and outbound traffic except server communication",
        "DISABLE_NIC": "Disable network adapter completely",
        "HYBRID": "Firewall block with NIC disable fallback",
        "OUTBOUND_ONLY_BLOCK": "Block outbound traffic, allow inbound from server",
        "RANSOMRUN_CONTROLLED": "Allow only server communication and DNS",
        "SEGMENT_QUARANTINE_SIM": "Quarantine tagging with lateral movement blocking"
    }
    return descriptions.get(policy, "Unknown policy")
