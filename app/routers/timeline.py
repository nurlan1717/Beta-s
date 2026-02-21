"""
IR Timeline API endpoints.

Provides a unified incident response timeline showing all events during a Run:
- Run lifecycle events
- Task lifecycle events
- Detection/alerts
- Playbook/response actions
- Snapshot events
- Rollback events
- Recovery events
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc
from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import csv
import io

from ..database import get_db
from ..models import (
    Run, RunEvent, Task, Alert, EventType,
    ResponseExecution, RollbackPlan, BackupSnapshot
)
from ..deps.auth import require_user

router = APIRouter(prefix="/api/runs", tags=["timeline"])

# Event category mapping for filtering
EVENT_CATEGORIES = {
    "system": [
        EventType.RUN_CREATED, EventType.RUN_STARTED, EventType.RUN_COMPLETED, 
        EventType.RUN_FAILED, EventType.STOP_REQUESTED, EventType.STOP_EXECUTED
    ],
    "tasks": [
        EventType.TASK_ASSIGNED, EventType.TASK_SENT, EventType.TASK_STARTED,
        EventType.TASK_COMPLETED, EventType.TASK_FAILED
    ],
    "simulation": [
        EventType.FILE_RENAMED, EventType.FILE_QUARANTINED, EventType.RANSOM_NOTE_CREATED,
        EventType.VSSADMIN_EXECUTED, EventType.PERSISTENCE_CREATED, EventType.EXFIL_PREPARED
    ],
    "alerts": [
        EventType.ALERT_RECEIVED, EventType.DETECTION_CONFIRMED
    ],
    "response": [
        EventType.PLAYBOOK_TRIGGERED, EventType.RESPONSE_TASK_CREATED, EventType.RESPONSE_EXECUTED,
        EventType.HOST_ISOLATED, EventType.HOST_DEISOLATED, EventType.CONTAINMENT_STARTED,
        EventType.CONTAINMENT_COMPLETED,
        # New containment events
        EventType.HOST_ISOLATION_REQUESTED, EventType.HOST_RESTORE_REQUESTED,
        EventType.HOST_NETWORK_RESTORED, EventType.PATH_BLOCK_REQUESTED, EventType.PATH_BLOCKED,
        EventType.QUARANTINE_REQUESTED, EventType.RANSOMWARE_ARTIFACTS_RECEIVED
    ],
    "rollback": [
        EventType.SNAPSHOT_CREATED, EventType.SNAPSHOT_FAILED,
        EventType.ROLLBACK_PLANNED, EventType.ROLLBACK_APPROVED, EventType.ROLLBACK_STARTED,
        EventType.ROLLBACK_FILE_RESTORED, EventType.ROLLBACK_FILE_CONFLICT, EventType.ROLLBACK_FILE_FAILED,
        EventType.ROLLBACK_VERIFY_STARTED, EventType.ROLLBACK_VERIFY_COMPLETED,
        EventType.ROLLBACK_COMPLETED, EventType.ROLLBACK_FAILED
    ],
    "recovery": [
        EventType.RECOVERY_STARTED, EventType.RECOVERY_COMPLETED, EventType.RECOVERY_FAILED
    ]
}

# Event severity mapping
EVENT_SEVERITY = {
    EventType.RUN_FAILED: "critical",
    EventType.TASK_FAILED: "high",
    EventType.ALERT_RECEIVED: "high",
    EventType.DETECTION_CONFIRMED: "critical",
    EventType.HOST_ISOLATED: "high",
    EventType.ROLLBACK_FAILED: "critical",
    EventType.ROLLBACK_FILE_FAILED: "medium",
    EventType.RECOVERY_FAILED: "critical",
    EventType.SNAPSHOT_FAILED: "high",
    # Containment events
    EventType.HOST_ISOLATION_REQUESTED: "high",
    EventType.HOST_NETWORK_RESTORED: "medium",
    EventType.PATH_BLOCKED: "high",
    EventType.QUARANTINE_REQUESTED: "medium",
}

# Event icons mapping
EVENT_ICONS = {
    EventType.RUN_CREATED: "bi-play-circle",
    EventType.RUN_STARTED: "bi-play-fill",
    EventType.RUN_COMPLETED: "bi-check-circle",
    EventType.RUN_FAILED: "bi-x-circle",
    EventType.TASK_ASSIGNED: "bi-clipboard-check",
    EventType.TASK_SENT: "bi-send",
    EventType.TASK_STARTED: "bi-gear-wide-connected",
    EventType.TASK_COMPLETED: "bi-check2-circle",
    EventType.TASK_FAILED: "bi-exclamation-triangle",
    EventType.FILE_RENAMED: "bi-file-earmark-lock",
    EventType.RANSOM_NOTE_CREATED: "bi-file-earmark-text",
    EventType.ALERT_RECEIVED: "bi-bell",
    EventType.DETECTION_CONFIRMED: "bi-shield-exclamation",
    EventType.PLAYBOOK_TRIGGERED: "bi-book",
    EventType.RESPONSE_EXECUTED: "bi-lightning",
    EventType.HOST_ISOLATED: "bi-shield-lock",
    EventType.HOST_DEISOLATED: "bi-unlock",
    EventType.SNAPSHOT_CREATED: "bi-camera",
    EventType.ROLLBACK_PLANNED: "bi-arrow-counterclockwise",
    EventType.ROLLBACK_APPROVED: "bi-check2-square",
    EventType.ROLLBACK_STARTED: "bi-arrow-repeat",
    EventType.ROLLBACK_COMPLETED: "bi-arrow-counterclockwise",
    EventType.ROLLBACK_FAILED: "bi-x-octagon",
    EventType.RECOVERY_STARTED: "bi-heart-pulse",
    EventType.RECOVERY_COMPLETED: "bi-heart",
    # Containment events
    EventType.HOST_ISOLATION_REQUESTED: "bi-wifi-off",
    EventType.HOST_RESTORE_REQUESTED: "bi-wifi",
    EventType.HOST_NETWORK_RESTORED: "bi-shield-check",
    EventType.PATH_BLOCK_REQUESTED: "bi-slash-circle",
    EventType.PATH_BLOCKED: "bi-x-circle-fill",
    EventType.QUARANTINE_REQUESTED: "bi-box-arrow-in-right",
    EventType.RANSOMWARE_ARTIFACTS_RECEIVED: "bi-folder-symlink",
}


def get_event_category(event_type: EventType) -> str:
    """Get the category for an event type."""
    for category, types in EVENT_CATEGORIES.items():
        if event_type in types:
            return category
    return "system"


def get_event_severity(event_type: EventType) -> str:
    """Get severity level for an event type."""
    return EVENT_SEVERITY.get(event_type, "info")


def get_event_icon(event_type: EventType) -> str:
    """Get Bootstrap icon class for an event type."""
    return EVENT_ICONS.get(event_type, "bi-circle")


def calculate_ir_metrics(events: List[RunEvent], run: Run) -> Dict[str, Any]:
    """Calculate IR metrics from timeline events."""
    metrics = {
        "time_to_detect": None,
        "time_to_contain": None,
        "time_to_recover": None,
        "total_alerts": 0,
        "total_tasks": 0,
        "failed_tasks": 0,
        "rollback_performed": False,
        "files_restored": 0
    }
    
    run_start = run.started_at
    first_alert = None
    first_containment = None
    recovery_complete = None
    
    for event in events:
        if event.event_type == EventType.ALERT_RECEIVED:
            metrics["total_alerts"] += 1
            if first_alert is None:
                first_alert = event.timestamp
        
        elif event.event_type in [EventType.TASK_COMPLETED, EventType.TASK_FAILED]:
            metrics["total_tasks"] += 1
            if event.event_type == EventType.TASK_FAILED:
                metrics["failed_tasks"] += 1
        
        elif event.event_type == EventType.HOST_ISOLATED:
            if first_containment is None:
                first_containment = event.timestamp
        
        elif event.event_type == EventType.ROLLBACK_COMPLETED:
            metrics["rollback_performed"] = True
            recovery_complete = event.timestamp
            if event.details and isinstance(event.details, dict):
                metrics["files_restored"] = event.details.get("files_restored", 0)
        
        elif event.event_type == EventType.RUN_COMPLETED:
            if recovery_complete is None:
                recovery_complete = event.timestamp
    
    # Calculate time deltas
    if run_start and first_alert:
        metrics["time_to_detect"] = (first_alert - run_start).total_seconds()
    
    if first_alert and first_containment:
        metrics["time_to_contain"] = (first_containment - first_alert).total_seconds()
    
    if first_containment and recovery_complete:
        metrics["time_to_recover"] = (recovery_complete - first_containment).total_seconds()
    
    return metrics


def normalize_event(event: RunEvent, run_start: datetime = None) -> Dict[str, Any]:
    """Normalize a RunEvent into a timeline item."""
    relative_time = None
    if run_start and event.timestamp:
        delta = event.timestamp - run_start
        relative_time = delta.total_seconds()
    
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "relative_seconds": relative_time,
        "event_type": event.event_type.value if event.event_type else "UNKNOWN",
        "category": get_event_category(event.event_type) if event.event_type else "system",
        "severity": get_event_severity(event.event_type) if event.event_type else "info",
        "icon": get_event_icon(event.event_type) if event.event_type else "bi-circle",
        "title": format_event_title(event),
        "description": format_event_description(event),
        "details": event.details if event.details else {},
        "host_id": event.host_id,
        "run_id": event.run_id
    }


def format_event_title(event: RunEvent) -> str:
    """Generate a human-readable title for an event."""
    titles = {
        EventType.RUN_CREATED: "Run Created",
        EventType.RUN_STARTED: "Simulation Started",
        EventType.RUN_COMPLETED: "Run Completed",
        EventType.RUN_FAILED: "Run Failed",
        EventType.TASK_ASSIGNED: "Task Assigned",
        EventType.TASK_SENT: "Task Sent to Agent",
        EventType.TASK_STARTED: "Task Execution Started",
        EventType.TASK_COMPLETED: "Task Completed",
        EventType.TASK_FAILED: "Task Failed",
        EventType.FILE_RENAMED: "File Encrypted/Renamed",
        EventType.FILE_QUARANTINED: "File Quarantined",
        EventType.RANSOM_NOTE_CREATED: "Ransom Note Created",
        EventType.VSSADMIN_EXECUTED: "Shadow Copy Deleted",
        EventType.PERSISTENCE_CREATED: "Persistence Mechanism Created",
        EventType.EXFIL_PREPARED: "Exfiltration Prepared",
        EventType.ALERT_RECEIVED: "Alert Received",
        EventType.DETECTION_CONFIRMED: "Detection Confirmed",
        EventType.PLAYBOOK_TRIGGERED: "Playbook Triggered",
        EventType.RESPONSE_TASK_CREATED: "Response Task Created",
        EventType.RESPONSE_EXECUTED: "Response Action Executed",
        EventType.HOST_ISOLATED: "Host Isolated",
        EventType.HOST_DEISOLATED: "Host De-isolated",
        EventType.CONTAINMENT_STARTED: "Containment Started",
        EventType.CONTAINMENT_COMPLETED: "Containment Completed",
        EventType.SNAPSHOT_CREATED: "Baseline Snapshot Created",
        EventType.SNAPSHOT_FAILED: "Snapshot Creation Failed",
        EventType.ROLLBACK_PLANNED: "Rollback Plan Created",
        EventType.ROLLBACK_APPROVED: "Rollback Approved",
        EventType.ROLLBACK_STARTED: "Rollback Execution Started",
        EventType.ROLLBACK_FILE_RESTORED: "File Restored",
        EventType.ROLLBACK_FILE_CONFLICT: "File Conflict Detected",
        EventType.ROLLBACK_FILE_FAILED: "File Restore Failed",
        EventType.ROLLBACK_VERIFY_STARTED: "Hash Verification Started",
        EventType.ROLLBACK_VERIFY_COMPLETED: "Hash Verification Completed",
        EventType.ROLLBACK_COMPLETED: "Rollback Completed",
        EventType.ROLLBACK_FAILED: "Rollback Failed",
        EventType.RECOVERY_STARTED: "Recovery Started",
        EventType.RECOVERY_COMPLETED: "Recovery Completed",
        EventType.RECOVERY_FAILED: "Recovery Failed",
        EventType.STOP_REQUESTED: "Stop Requested",
        EventType.STOP_EXECUTED: "Run Stopped",
    }
    return titles.get(event.event_type, event.event_type.value if event.event_type else "Unknown Event")


def format_event_description(event: RunEvent) -> str:
    """Generate a description from event details."""
    if not event.details:
        return ""
    
    details = event.details
    if isinstance(details, str):
        return details
    
    # Extract common fields
    parts = []
    if "task_type" in details:
        parts.append(f"Task: {details['task_type']}")
    if "file_path" in details:
        parts.append(f"File: {details['file_path']}")
    if "alert_id" in details:
        parts.append(f"Alert ID: {details['alert_id']}")
    if "rule_id" in details:
        parts.append(f"Rule: {details['rule_id']}")
    if "playbook_name" in details:
        parts.append(f"Playbook: {details['playbook_name']}")
    if "plan_id" in details:
        parts.append(f"Plan: #{details['plan_id']}")
    if "error" in details:
        parts.append(f"Error: {details['error']}")
    if "message" in details:
        parts.append(details['message'])
    
    return " | ".join(parts) if parts else ""


@router.get("/{run_id}/timeline")
def get_run_timeline(
    run_id: int,
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(500, le=1000),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """
    Get the full IR timeline for a run.
    
    Returns normalized timeline items sorted by timestamp, with IR metrics.
    """
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    # Query events
    query = db.query(RunEvent).filter(RunEvent.run_id == run_id)
    
    # Apply category filter
    if category and category in EVENT_CATEGORIES:
        category_types = EVENT_CATEGORIES[category]
        query = query.filter(RunEvent.event_type.in_(category_types))
    
    events = query.order_by(asc(RunEvent.timestamp)).limit(limit).all()
    
    # Normalize events
    run_start = run.started_at
    timeline_items = [normalize_event(e, run_start) for e in events]
    
    # Calculate metrics
    all_events = db.query(RunEvent).filter(RunEvent.run_id == run_id).all()
    metrics = calculate_ir_metrics(all_events, run)
    
    return {
        "run_id": run_id,
        "run_status": run.status.value if run.status else "UNKNOWN",
        "run_started_at": run.started_at.isoformat() if run.started_at else None,
        "run_completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "total_events": len(timeline_items),
        "metrics": metrics,
        "categories": list(EVENT_CATEGORIES.keys()),
        "timeline": timeline_items
    }


@router.get("/{run_id}/timeline/summary")
def get_timeline_summary(
    run_id: int,
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Get a summary of timeline events by category."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    events = db.query(RunEvent).filter(RunEvent.run_id == run_id).all()
    
    # Count by category
    summary = {cat: 0 for cat in EVENT_CATEGORIES.keys()}
    for event in events:
        cat = get_event_category(event.event_type)
        summary[cat] += 1
    
    # Calculate metrics
    metrics = calculate_ir_metrics(events, run)
    
    # Key events
    key_events = []
    key_types = [
        EventType.RUN_STARTED, EventType.ALERT_RECEIVED, EventType.HOST_ISOLATED,
        EventType.ROLLBACK_COMPLETED, EventType.RUN_COMPLETED
    ]
    for event in events:
        if event.event_type in key_types:
            key_events.append(normalize_event(event, run.started_at))
    
    return {
        "run_id": run_id,
        "total_events": len(events),
        "by_category": summary,
        "metrics": metrics,
        "key_events": key_events[:10]  # Top 10 key events
    }


@router.get("/{run_id}/timeline/export")
def export_timeline(
    run_id: int,
    format: str = Query("json", regex="^(json|csv)$"),
    db: Session = Depends(get_db),
    user = Depends(require_user)
):
    """Export timeline in JSON or CSV format."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    events = db.query(RunEvent).filter(RunEvent.run_id == run_id).order_by(asc(RunEvent.timestamp)).all()
    run_start = run.started_at
    timeline_items = [normalize_event(e, run_start) for e in events]
    
    if format == "json":
        content = json.dumps({
            "run_id": run_id,
            "exported_at": datetime.utcnow().isoformat(),
            "total_events": len(timeline_items),
            "timeline": timeline_items
        }, indent=2)
        
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=timeline_run_{run_id}.json"}
        )
    
    else:  # CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "relative_seconds", "event_type", "category", "severity", "title", "description"])
        
        for item in timeline_items:
            writer.writerow([
                item["timestamp"],
                item["relative_seconds"],
                item["event_type"],
                item["category"],
                item["severity"],
                item["title"],
                item["description"]
            ])
        
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=timeline_run_{run_id}.csv"}
        )
