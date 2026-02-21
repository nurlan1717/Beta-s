"""
IR Timeline Builder Module.

Maps existing run data (tasks, alerts, events) to standard IR lifecycle phases
and builds a unified, ordered timeline of events.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from sqlalchemy.orm import Session

from ..models import (
    Run, Task, Alert, RunEvent, EventType, IRPhase, IRPhaseStatus,
    IRPhaseStatusType, TaskStatus, RunStatus
)


# Event type to IR phase mapping
EVENT_PHASE_MAPPING = {
    # Preparation phase
    EventType.RUN_CREATED: IRPhase.PREPARATION,
    EventType.RUN_STARTED: IRPhase.PREPARATION,
    EventType.TASK_ASSIGNED: IRPhase.PREPARATION,
    
    # Identification phase
    EventType.ALERT_RECEIVED: IRPhase.IDENTIFICATION,
    EventType.DETECTION_CONFIRMED: IRPhase.IDENTIFICATION,
    EventType.TASK_STARTED: IRPhase.IDENTIFICATION,
    EventType.FILE_RENAMED: IRPhase.IDENTIFICATION,
    EventType.RANSOM_NOTE_CREATED: IRPhase.IDENTIFICATION,
    EventType.VSSADMIN_EXECUTED: IRPhase.IDENTIFICATION,
    EventType.PERSISTENCE_CREATED: IRPhase.IDENTIFICATION,
    EventType.EXFIL_PREPARED: IRPhase.IDENTIFICATION,
    EventType.RANSOMWARE_ARTIFACTS_RECEIVED: IRPhase.IDENTIFICATION,
    
    # Containment phase
    EventType.CONTAINMENT_STARTED: IRPhase.CONTAINMENT,
    EventType.CONTAINMENT_COMPLETED: IRPhase.CONTAINMENT,
    EventType.HOST_ISOLATION_REQUESTED: IRPhase.CONTAINMENT,
    EventType.HOST_ISOLATED: IRPhase.CONTAINMENT,
    EventType.HOST_ISOLATION_FAILED: IRPhase.CONTAINMENT,
    EventType.PATH_BLOCK_REQUESTED: IRPhase.CONTAINMENT,
    EventType.PATH_BLOCKED: IRPhase.CONTAINMENT,
    EventType.QUARANTINE_REQUESTED: IRPhase.CONTAINMENT,
    EventType.FILE_QUARANTINED: IRPhase.CONTAINMENT,
    EventType.PLAYBOOK_TRIGGERED: IRPhase.CONTAINMENT,
    EventType.RESPONSE_TASK_CREATED: IRPhase.CONTAINMENT,
    EventType.RESPONSE_EXECUTED: IRPhase.CONTAINMENT,
    
    # Eradication phase (currently limited - extend as needed)
    EventType.STOP_REQUESTED: IRPhase.ERADICATION,
    EventType.STOP_EXECUTED: IRPhase.ERADICATION,
    
    # Recovery phase
    EventType.HOST_RESTORE_REQUESTED: IRPhase.RECOVERY,
    EventType.HOST_NETWORK_RESTORED: IRPhase.RECOVERY,
    EventType.HOST_DEISOLATED: IRPhase.RECOVERY,
    
    # Completion
    EventType.RUN_COMPLETED: IRPhase.RECOVERY,
    EventType.RUN_FAILED: IRPhase.RECOVERY,
}

# Task type to IR phase mapping
TASK_PHASE_MAPPING = {
    "simulate_ransomware": IRPhase.PREPARATION,
    "ransomware_simulation": IRPhase.PREPARATION,
    "containment_isolate_host": IRPhase.CONTAINMENT,
    "containment_block_path": IRPhase.CONTAINMENT,
    "containment_quarantine_file": IRPhase.CONTAINMENT,
    "containment_restore_network": IRPhase.RECOVERY,
    "kill_process": IRPhase.ERADICATION,
    "disable_persistence": IRPhase.ERADICATION,
    "remove_scheduled_task": IRPhase.ERADICATION,
    "delete_malware_artifact": IRPhase.ERADICATION,
    "restore_files": IRPhase.RECOVERY,
    "restore_backup": IRPhase.RECOVERY,
    "rollback": IRPhase.RECOVERY,
}


@dataclass
class TimelineEvent:
    """Represents a single event in the IR timeline."""
    timestamp: datetime
    phase: str
    type: str
    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    mitre: Optional[str] = None
    source: str = "system"  # agent, elk, system
    evidence_ref: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "phase": self.phase,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "mitre": self.mitre,
            "source": self.source,
            "evidence_ref": self.evidence_ref
        }


class IRTimelineBuilder:
    """
    Builds a unified IR timeline from run data.
    
    Maps existing data sources (tasks, alerts, events) to the standard
    IR lifecycle phases and produces an ordered list of timeline events.
    """
    
    # MITRE ATT&CK technique mapping for common rule IDs
    MITRE_MAPPING = {
        "RR-2001": "T1486",  # Data Encrypted for Impact
        "RR-2002": "T1486",
        "RR-2003": "T1490",  # Inhibit System Recovery
        "RR-2004": "T1490",
        "RR-2005": "T1059",  # Command and Scripting Interpreter
        "RR-2006": "T1547",  # Boot or Logon Autostart Execution
        "RR-2007": "T1053",  # Scheduled Task/Job
        "RR-2008": "T1055",  # Process Injection
        "RR-2009": "T1083",  # File and Directory Discovery
        "RR-2010": "T1082",  # System Information Discovery
    }
    
    def __init__(self, db: Session, run_id: int):
        self.db = db
        self.run_id = run_id
        self.run: Optional[Run] = None
        self.timeline: List[TimelineEvent] = []
        self.phase_data: Dict[str, Dict] = {}
        
    def build(self) -> Dict[str, Any]:
        """
        Build the complete IR timeline for the run.
        
        Returns:
            Dictionary containing phases, timeline events, and metadata.
        """
        # Load run data
        self.run = self.db.query(Run).filter(Run.id == self.run_id).first()
        if not self.run:
            return {"error": "Run not found", "run_id": self.run_id}
        
        # Initialize phase data
        self._init_phases()
        
        # Collect events from all sources
        self._collect_run_events()
        self._collect_task_events()
        self._collect_alert_events()
        
        # Sort timeline by timestamp
        self.timeline.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min)
        
        # Deduplicate similar events
        self._deduplicate_events()
        
        # Calculate phase statuses
        self._calculate_phase_statuses()
        
        return {
            "run_id": self.run_id,
            "run_status": self.run.status.value if self.run.status else None,
            "started_at": self.run.started_at.isoformat() if self.run.started_at else None,
            "ended_at": self.run.ended_at.isoformat() if self.run.ended_at else None,
            "phases": self._get_phases_summary(),
            "timeline": [e.to_dict() for e in self.timeline],
            "event_count": len(self.timeline),
            "metadata": {
                "scenario": self.run.scenario.name if self.run.scenario else None,
                "host": self.run.host.name if self.run.host else None,
            }
        }
    
    def _init_phases(self):
        """Initialize phase tracking data."""
        for phase in IRPhase:
            self.phase_data[phase.value] = {
                "phase": phase.value,
                "status": IRPhaseStatusType.NOT_STARTED.value,
                "started_at": None,
                "completed_at": None,
                "event_count": 0,
                "events": []
            }
    
    def _collect_run_events(self):
        """Collect events from RunEvent table."""
        events = self.db.query(RunEvent).filter(
            RunEvent.run_id == self.run_id
        ).order_by(RunEvent.timestamp).all()
        
        for event in events:
            phase = EVENT_PHASE_MAPPING.get(event.event_type, IRPhase.IDENTIFICATION)
            
            # Determine severity based on event type
            severity = self._get_event_severity(event.event_type)
            
            timeline_event = TimelineEvent(
                timestamp=event.timestamp,
                phase=phase.value,
                type=event.event_type.value if event.event_type else "UNKNOWN",
                title=self._format_event_title(event.event_type),
                description=event.details.get("message", "") if event.details else "",
                severity=severity,
                source="system",
                evidence_ref={"event_id": event.id, "details": event.details}
            )
            
            self.timeline.append(timeline_event)
            self.phase_data[phase.value]["events"].append(timeline_event)
            self.phase_data[phase.value]["event_count"] += 1
    
    def _collect_task_events(self):
        """Collect events from Task table."""
        tasks = self.db.query(Task).filter(
            Task.run_id == self.run_id
        ).order_by(Task.created_at).all()
        
        for task in tasks:
            phase = TASK_PHASE_MAPPING.get(task.type, IRPhase.PREPARATION)
            
            # Task created event
            timeline_event = TimelineEvent(
                timestamp=task.created_at,
                phase=phase.value,
                type=f"TASK_{task.type.upper()}",
                title=f"Task: {self._format_task_type(task.type)}",
                description=f"Status: {task.status.value}" if task.status else "",
                severity="info" if task.status == TaskStatus.COMPLETED else "medium",
                source="agent",
                evidence_ref={
                    "task_id": task.id,
                    "type": task.type,
                    "status": task.status.value if task.status else None,
                    "parameters": task.parameters,
                    "result": task.result_message
                }
            )
            
            self.timeline.append(timeline_event)
            self.phase_data[phase.value]["events"].append(timeline_event)
            self.phase_data[phase.value]["event_count"] += 1
    
    def _collect_alert_events(self):
        """Collect events from Alert table (ELK/SIEM alerts)."""
        alerts = self.db.query(Alert).filter(
            Alert.run_id == self.run_id
        ).order_by(Alert.timestamp).all()
        
        seen_rules = set()  # Track seen rule IDs for deduplication
        
        for alert in alerts:
            # Skip duplicate alerts with same rule_id within short timeframe
            rule_key = f"{alert.rule_id}_{alert.timestamp.strftime('%Y%m%d%H%M') if alert.timestamp else ''}"
            if rule_key in seen_rules:
                continue
            seen_rules.add(rule_key)
            
            # Get MITRE technique
            mitre = self.MITRE_MAPPING.get(alert.rule_id)
            
            # Determine severity
            if alert.severity >= 12:
                severity = "critical"
            elif alert.severity >= 8:
                severity = "high"
            elif alert.severity >= 4:
                severity = "medium"
            else:
                severity = "low"
            
            timeline_event = TimelineEvent(
                timestamp=alert.timestamp,
                phase=IRPhase.IDENTIFICATION.value,
                type="ALERT",
                title=f"Alert: {alert.rule_id}",
                description=alert.rule_description or "",
                severity=severity,
                mitre=mitre,
                source="elk",
                evidence_ref={
                    "alert_id": alert.id,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "agent_name": alert.agent_name,
                    "raw": alert.raw
                }
            )
            
            self.timeline.append(timeline_event)
            self.phase_data[IRPhase.IDENTIFICATION.value]["events"].append(timeline_event)
            self.phase_data[IRPhase.IDENTIFICATION.value]["event_count"] += 1
    
    def _deduplicate_events(self):
        """Remove duplicate or very similar events."""
        if len(self.timeline) <= 1:
            return
        
        deduped = [self.timeline[0]]
        
        for event in self.timeline[1:]:
            last = deduped[-1]
            
            # Skip if same type and title within 2 seconds
            if (event.type == last.type and 
                event.title == last.title and
                event.timestamp and last.timestamp):
                time_diff = abs((event.timestamp - last.timestamp).total_seconds())
                if time_diff < 2:
                    continue
            
            deduped.append(event)
        
        self.timeline = deduped
    
    def _calculate_phase_statuses(self):
        """Calculate status for each IR phase based on events."""
        for phase_name, data in self.phase_data.items():
            events = data["events"]
            
            if not events:
                data["status"] = IRPhaseStatusType.NOT_STARTED.value
                continue
            
            # Get timestamps
            timestamps = [e.timestamp for e in events if e.timestamp]
            if timestamps:
                data["started_at"] = min(timestamps).isoformat()
                data["completed_at"] = max(timestamps).isoformat()
            
            # Determine status based on run status and events
            if self.run.status in [RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELED] or self.run.ended_at:
                data["status"] = IRPhaseStatusType.COMPLETED.value
            elif events:
                data["status"] = IRPhaseStatusType.IN_PROGRESS.value
    
    def _get_phases_summary(self) -> List[Dict]:
        """Get summary of all phases."""
        phases = []
        for phase in IRPhase:
            phase_info = self.phase_data.get(phase.value, {})
            phases.append({
                "phase": phase.value,
                "display_name": phase.value.replace("_", " ").title(),
                "status": phase_info.get("status", IRPhaseStatusType.NOT_STARTED.value),
                "started_at": phase_info.get("started_at"),
                "completed_at": phase_info.get("completed_at"),
                "event_count": phase_info.get("event_count", 0)
            })
        return phases
    
    def _get_event_severity(self, event_type: EventType) -> str:
        """Get severity level for an event type."""
        critical_events = [
            EventType.HOST_ISOLATED, EventType.RANSOM_NOTE_CREATED,
            EventType.RUN_FAILED
        ]
        high_events = [
            EventType.VSSADMIN_EXECUTED, EventType.PERSISTENCE_CREATED,
            EventType.EXFIL_PREPARED, EventType.HOST_ISOLATION_FAILED
        ]
        medium_events = [
            EventType.FILE_RENAMED, EventType.CONTAINMENT_STARTED
        ]
        
        if event_type in critical_events:
            return "critical"
        elif event_type in high_events:
            return "high"
        elif event_type in medium_events:
            return "medium"
        else:
            return "info"
    
    def _format_event_title(self, event_type: EventType) -> str:
        """Format event type as human-readable title."""
        if not event_type:
            return "Unknown Event"
        return event_type.value.replace("_", " ").title()
    
    def _format_task_type(self, task_type: str) -> str:
        """Format task type as human-readable string."""
        return task_type.replace("_", " ").title()


def build_ir_timeline(db: Session, run_id: int) -> Dict[str, Any]:
    """
    Convenience function to build IR timeline for a run.
    
    Args:
        db: Database session
        run_id: ID of the run
        
    Returns:
        Dictionary containing timeline data
    """
    builder = IRTimelineBuilder(db, run_id)
    return builder.build()
