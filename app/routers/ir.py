"""
IR (Incident Response) Router.

Provides API endpoints for IR timeline and lessons learned features.
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db
from ..models import (
    Run, LessonsLearned, LessonsActionItem, IRPhaseStatus,
    ActionItemPriority, ActionItemStatus
)
from ..ir.timeline import build_ir_timeline, IRTimelineBuilder
from ..ir.lessons import generate_lessons_learned, LessonsLearnedGenerator

router = APIRouter(prefix="/api/runs", tags=["ir"])


# =============================================================================
# Pydantic Schemas
# =============================================================================

class ActionItemUpdate(BaseModel):
    """Schema for updating an action item."""
    owner: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None
    due_date: Optional[datetime] = None


class ActionItemCreate(BaseModel):
    """Schema for creating a new action item."""
    item: str
    priority: str = "MEDIUM"
    category: Optional[str] = None
    owner: Optional[str] = None
    due_date: Optional[datetime] = None


# =============================================================================
# Timeline Endpoints
# =============================================================================

@router.get("/{run_id}/ir/timeline")
async def get_ir_timeline(run_id: int, db: Session = Depends(get_db)):
    """
    Get the IR timeline for a run.
    
    Returns phases, timeline events, and metadata organized by IR lifecycle.
    """
    # Verify run exists
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    timeline_data = build_ir_timeline(db, run_id)
    return timeline_data


@router.get("/{run_id}/ir/phases")
async def get_ir_phases(run_id: int, db: Session = Depends(get_db)):
    """
    Get just the phase status summary for a run.
    """
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    builder = IRTimelineBuilder(db, run_id)
    timeline_data = builder.build()
    
    return {
        "run_id": run_id,
        "phases": timeline_data.get("phases", [])
    }


# =============================================================================
# Lessons Learned Endpoints
# =============================================================================

@router.get("/{run_id}/ir/lessons")
async def get_lessons_learned(run_id: int, db: Session = Depends(get_db)):
    """
    Get existing lessons learned for a run.
    
    Returns 404 if not yet generated.
    """
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    lessons = db.query(LessonsLearned).filter(
        LessonsLearned.run_id == run_id
    ).first()
    
    if not lessons:
        return {
            "run_id": run_id,
            "exists": False,
            "message": "Lessons learned not yet generated. Use POST to generate."
        }
    
    # Get action items
    action_items = db.query(LessonsActionItem).filter(
        LessonsActionItem.lessons_learned_id == lessons.id
    ).order_by(LessonsActionItem.priority.desc()).all()
    
    return {
        "run_id": run_id,
        "exists": True,
        "lessons_learned_id": lessons.id,
        "summary": lessons.summary,
        "what_went_well": lessons.what_went_well or [],
        "what_went_wrong": lessons.what_went_wrong or [],
        "metrics": {
            "time_to_detect_seconds": lessons.time_to_detect_seconds,
            "time_to_contain_seconds": lessons.time_to_contain_seconds,
            "time_to_recover_seconds": lessons.time_to_recover_seconds,
            "total_duration_seconds": lessons.total_duration_seconds,
            "affected_files_count": lessons.affected_files_count,
            "affected_endpoints_count": lessons.affected_endpoints_count,
            "high_severity_alerts_count": lessons.high_severity_alerts_count,
            "total_alerts_count": lessons.total_alerts_count,
            "mitre_techniques": lessons.mitre_techniques or []
        },
        "action_items": [
            {
                "id": item.id,
                "item": item.item,
                "priority": item.priority.value if item.priority else "MEDIUM",
                "category": item.category,
                "owner": item.owner,
                "due_date": item.due_date.isoformat() if item.due_date else None,
                "status": item.status.value if item.status else "OPEN",
                "notes": item.notes
            }
            for item in action_items
        ],
        "created_at": lessons.created_at.isoformat() if lessons.created_at else None,
        "updated_at": lessons.updated_at.isoformat() if lessons.updated_at else None
    }


@router.post("/{run_id}/ir/lessons/generate")
async def generate_lessons(run_id: int, db: Session = Depends(get_db)):
    """
    Generate lessons learned for a run.
    
    Analyzes run data to produce:
    - Summary
    - What went well / what went wrong
    - Key metrics (TTD, TTC, TTR)
    - Action items
    """
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    try:
        data = generate_lessons_learned(db, run_id, save=True)
        return {
            "success": True,
            "message": "Lessons learned generated successfully",
            "data": data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{run_id}/ir/lessons/action-items/{item_id}")
async def update_action_item(
    run_id: int,
    item_id: int,
    update: ActionItemUpdate,
    db: Session = Depends(get_db)
):
    """
    Update an action item (owner, status, notes, due_date).
    """
    item = db.query(LessonsActionItem).filter(
        LessonsActionItem.id == item_id,
        LessonsActionItem.run_id == run_id
    ).first()
    
    if not item:
        raise HTTPException(status_code=404, detail="Action item not found")
    
    if update.owner is not None:
        item.owner = update.owner
    if update.status is not None:
        try:
            item.status = ActionItemStatus(update.status)
            if update.status == "COMPLETED":
                item.completed_at = datetime.utcnow()
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {update.status}")
    if update.notes is not None:
        item.notes = update.notes
    if update.due_date is not None:
        item.due_date = update.due_date
    
    db.commit()
    
    return {
        "success": True,
        "item": {
            "id": item.id,
            "item": item.item,
            "priority": item.priority.value if item.priority else "MEDIUM",
            "category": item.category,
            "owner": item.owner,
            "status": item.status.value if item.status else "OPEN",
            "notes": item.notes,
            "due_date": item.due_date.isoformat() if item.due_date else None
        }
    }


@router.post("/{run_id}/ir/lessons/action-items")
async def create_action_item(
    run_id: int,
    item_data: ActionItemCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new action item manually.
    """
    # Get lessons learned
    lessons = db.query(LessonsLearned).filter(
        LessonsLearned.run_id == run_id
    ).first()
    
    if not lessons:
        raise HTTPException(
            status_code=400,
            detail="Generate lessons learned first before adding action items"
        )
    
    try:
        priority = ActionItemPriority(item_data.priority)
    except ValueError:
        priority = ActionItemPriority.MEDIUM
    
    item = LessonsActionItem(
        run_id=run_id,
        lessons_learned_id=lessons.id,
        item=item_data.item,
        priority=priority,
        category=item_data.category,
        owner=item_data.owner,
        due_date=item_data.due_date,
        status=ActionItemStatus.OPEN
    )
    
    db.add(item)
    db.commit()
    
    return {
        "success": True,
        "item": {
            "id": item.id,
            "item": item.item,
            "priority": item.priority.value,
            "category": item.category,
            "owner": item.owner,
            "status": item.status.value,
            "due_date": item.due_date.isoformat() if item.due_date else None
        }
    }


# =============================================================================
# IR Report Export
# =============================================================================

@router.get("/{run_id}/ir-report")
async def get_ir_report(run_id: int, db: Session = Depends(get_db)):
    """
    Get complete IR report including timeline, phases, metrics, and lessons learned.
    
    This is the main export endpoint for the full incident report.
    """
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    # Build timeline
    timeline_data = build_ir_timeline(db, run_id)
    
    # Get lessons learned
    lessons = db.query(LessonsLearned).filter(
        LessonsLearned.run_id == run_id
    ).first()
    
    lessons_data = None
    action_items = []
    
    if lessons:
        action_items_db = db.query(LessonsActionItem).filter(
            LessonsActionItem.lessons_learned_id == lessons.id
        ).all()
        
        action_items = [
            {
                "id": item.id,
                "item": item.item,
                "priority": item.priority.value if item.priority else "MEDIUM",
                "category": item.category,
                "owner": item.owner,
                "status": item.status.value if item.status else "OPEN",
                "due_date": item.due_date.isoformat() if item.due_date else None
            }
            for item in action_items_db
        ]
        
        lessons_data = {
            "summary": lessons.summary,
            "what_went_well": lessons.what_went_well or [],
            "what_went_wrong": lessons.what_went_wrong or [],
            "metrics": {
                "time_to_detect_seconds": lessons.time_to_detect_seconds,
                "time_to_contain_seconds": lessons.time_to_contain_seconds,
                "time_to_recover_seconds": lessons.time_to_recover_seconds,
                "total_duration_seconds": lessons.total_duration_seconds,
                "affected_files_count": lessons.affected_files_count,
                "high_severity_alerts_count": lessons.high_severity_alerts_count,
                "total_alerts_count": lessons.total_alerts_count,
                "mitre_techniques": lessons.mitre_techniques or []
            }
        }
    
    return {
        "report_type": "IR_INCIDENT_REPORT",
        "generated_at": datetime.utcnow().isoformat(),
        "run": {
            "id": run.id,
            "status": run.status.value if run.status else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "ended_at": run.ended_at.isoformat() if run.ended_at else None,
            "scenario": run.scenario.name if run.scenario else None,
            "host": run.host.name if run.host else None
        },
        "phases": timeline_data.get("phases", []),
        "timeline": timeline_data.get("timeline", []),
        "event_count": timeline_data.get("event_count", 0),
        "lessons_learned": lessons_data,
        "action_items": action_items
    }
