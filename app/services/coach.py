"""
Adaptive Coach Mode - Post-Run Recommendations Service
=======================================================
Generates human-readable feedback for analysts after each run:
- What went well
- What can be improved
- What to study next
"""

from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from ..models import (
    Run, RunEvent, Alert, Task, AffectedFile, RunFeedback,
    User, IRSession, EventType, MITRE_MAPPING
)


def generate_run_feedback(
    db: Session,
    run: Run,
    user: Optional[User] = None,
    ir_session: Optional[IRSession] = None
) -> RunFeedback:
    """
    Generate coach feedback for a completed run.
    
    Args:
        db: Database session
        run: The completed Run
        user: Optional User who handled the run
        ir_session: Optional IR session with timing data
        
    Returns:
        RunFeedback with positives, negatives, and recommendations
    """
    # Gather data
    events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.timestamp).all()
    alerts = db.query(Alert).filter(Alert.run_id == run.id).order_by(Alert.timestamp).all()
    tasks = db.query(Task).filter(Task.run_id == run.id).all()
    affected_files = db.query(AffectedFile).filter(AffectedFile.run_id == run.id).all()
    
    # Calculate metrics
    metrics = _calculate_performance_metrics(run, events, alerts, tasks, affected_files, ir_session)
    
    # Generate feedback
    positives = _generate_positives(metrics, run, events, alerts)
    negatives = _generate_negatives(metrics, run, events, alerts, affected_files)
    recommendations = _generate_recommendations(metrics, run, events, alerts)
    
    # Check for existing feedback
    existing = db.query(RunFeedback).filter(RunFeedback.run_id == run.id).first()
    
    if existing:
        existing.positives = positives
        existing.negatives = negatives
        existing.recommendations = recommendations
        existing.user_id = user.id if user else existing.user_id
        db.commit()
        return existing
    
    # Create new feedback
    feedback = RunFeedback(
        run_id=run.id,
        user_id=user.id if user else None,
        positives=positives,
        negatives=negatives,
        recommendations=recommendations
    )
    
    db.add(feedback)
    db.commit()
    db.refresh(feedback)
    
    return feedback


def _calculate_performance_metrics(
    run: Run,
    events: List[RunEvent],
    alerts: List[Alert],
    tasks: List[Task],
    affected_files: List[AffectedFile],
    ir_session: Optional[IRSession]
) -> Dict:
    """Calculate performance metrics for feedback generation."""
    metrics = {
        "detection_latency_seconds": None,
        "response_latency_seconds": None,
        "containment_latency_seconds": None,
        "files_before_detection": 0,
        "files_before_response": 0,
        "total_files_affected": len(affected_files),
        "total_alerts": len(alerts),
        "high_severity_alerts": 0,
        "response_tasks_count": 0,
        "techniques_count": 0,
        "vssadmin_detected": False,
        "persistence_detected": False,
        "contained_before_completion": False
    }
    
    if not run.started_at:
        return metrics
    
    # Count high severity alerts
    metrics["high_severity_alerts"] = sum(1 for a in alerts if a.severity >= 10)
    
    # Count response tasks
    metrics["response_tasks_count"] = sum(1 for t in tasks if t.type.startswith("response_"))
    
    # Detection latency (time to first alert)
    if alerts:
        first_alert = alerts[0]
        if first_alert.timestamp:
            metrics["detection_latency_seconds"] = (
                first_alert.timestamp - run.started_at
            ).total_seconds()
    
    # Response latency (time to first response action)
    response_events = [e for e in events if e.event_type == EventType.RESPONSE_EXECUTED]
    if response_events and alerts:
        first_response = response_events[0]
        first_alert = alerts[0]
        if first_response.timestamp and first_alert.timestamp:
            metrics["response_latency_seconds"] = (
                first_response.timestamp - first_alert.timestamp
            ).total_seconds()
    
    # Containment latency
    isolation_events = [e for e in events if e.event_type == EventType.RESPONSE_EXECUTED]
    if isolation_events:
        first_isolation = isolation_events[0]
        if first_isolation.timestamp:
            metrics["containment_latency_seconds"] = (
                first_isolation.timestamp - run.started_at
            ).total_seconds()
    
    # Files affected before detection
    if alerts and affected_files:
        first_alert_time = alerts[0].timestamp
        if first_alert_time:
            metrics["files_before_detection"] = sum(
                1 for f in affected_files 
                if f.timestamp and f.timestamp < first_alert_time
            )
    
    # Check for specific detections
    for alert in alerts:
        if alert.rule_id == "100101":  # vssadmin
            metrics["vssadmin_detected"] = True
        if alert.rule_id == "100108":  # registry
            metrics["persistence_detected"] = True
    
    # Count unique techniques
    techniques = set()
    for alert in alerts:
        if alert.rule_id in MITRE_MAPPING:
            techniques.add(MITRE_MAPPING[alert.rule_id]["technique"])
    metrics["techniques_count"] = len(techniques)
    
    # Check if contained before run completed naturally
    if run.ended_at and response_events:
        last_response = response_events[-1]
        if last_response.timestamp and last_response.timestamp < run.ended_at:
            metrics["contained_before_completion"] = True
    
    return metrics


def _generate_positives(
    metrics: Dict,
    run: Run,
    events: List[RunEvent],
    alerts: List[Alert]
) -> str:
    """Generate positive feedback points."""
    positives = []
    
    # Fast detection
    detection = metrics.get("detection_latency_seconds")
    if detection is not None:
        if detection < 10:
            positives.append("• Excellent detection speed - attack identified within 10 seconds")
        elif detection < 30:
            positives.append("• Good detection speed - attack identified within 30 seconds")
        elif detection < 60:
            positives.append("• Reasonable detection time - attack identified within 1 minute")
    
    # Fast response
    response = metrics.get("response_latency_seconds")
    if response is not None:
        if response < 15:
            positives.append("• Rapid response - containment action taken within 15 seconds of first alert")
        elif response < 30:
            positives.append("• Good response time - action taken within 30 seconds of detection")
    
    # Detected critical events
    if metrics.get("vssadmin_detected"):
        positives.append("• Successfully detected shadow copy deletion attempt (T1490)")
    
    if metrics.get("persistence_detected"):
        positives.append("• Identified persistence mechanism installation")
    
    # Multiple techniques handled
    if metrics.get("techniques_count", 0) >= 3:
        positives.append(f"• Successfully handled multi-technique attack ({metrics['techniques_count']} MITRE techniques)")
    
    # Contained before completion
    if metrics.get("contained_before_completion"):
        positives.append("• Attack was contained before completing its full execution")
    
    # Response actions taken
    if metrics.get("response_tasks_count", 0) > 0:
        positives.append(f"• Executed {metrics['response_tasks_count']} automated response action(s)")
    
    # High severity alerts handled
    if metrics.get("high_severity_alerts", 0) > 0 and metrics.get("response_tasks_count", 0) > 0:
        positives.append("• Appropriately responded to high-severity alerts")
    
    if not positives:
        positives.append("• Simulation completed - review the timeline for learning opportunities")
    
    return "\n".join(positives)


def _generate_negatives(
    metrics: Dict,
    run: Run,
    events: List[RunEvent],
    alerts: List[Alert],
    affected_files: List[AffectedFile]
) -> str:
    """Generate areas for improvement."""
    negatives = []
    
    # Slow detection
    detection = metrics.get("detection_latency_seconds")
    if detection is not None:
        if detection > 120:
            negatives.append("• Detection was slow - attack ran for over 2 minutes before first alert")
        elif detection > 60:
            negatives.append("• Detection could be faster - consider additional monitoring rules")
    
    # Slow response
    response = metrics.get("response_latency_seconds")
    if response is not None:
        if response > 60:
            negatives.append("• Response was delayed - over 1 minute between detection and action")
        elif response > 30:
            negatives.append("• Response time could be improved - aim for under 30 seconds")
    elif metrics.get("total_alerts", 0) > 0 and metrics.get("response_tasks_count", 0) == 0:
        negatives.append("• No automated response actions were triggered despite alerts")
    
    # Many files affected
    files_affected = metrics.get("total_files_affected", 0)
    if files_affected > 50:
        negatives.append(f"• High file impact - {files_affected} files were affected before containment")
    elif files_affected > 20:
        negatives.append(f"• Moderate file impact - {files_affected} files affected")
    
    # Files affected before detection
    files_before = metrics.get("files_before_detection", 0)
    if files_before > 10:
        negatives.append(f"• {files_before} files were affected before the first alert was raised")
    
    # No detection of critical events
    if not metrics.get("vssadmin_detected"):
        # Check if vssadmin actually happened
        vss_events = [e for e in events if e.event_type == EventType.VSSADMIN_EXECUTED]
        if vss_events:
            negatives.append("• Shadow copy deletion occurred but was not detected by alerts")
    
    if not negatives:
        negatives.append("• No significant issues identified - good performance!")
    
    return "\n".join(negatives)


def _generate_recommendations(
    metrics: Dict,
    run: Run,
    events: List[RunEvent],
    alerts: List[Alert]
) -> str:
    """Generate actionable recommendations."""
    recommendations = []
    
    # Detection improvements
    detection = metrics.get("detection_latency_seconds")
    if detection is None or detection > 30:
        recommendations.append("• Review Wazuh rules for earlier detection of ransomware indicators")
        recommendations.append("• Consider adding rules for file rename patterns and mass file operations")
    
    # Response improvements
    response = metrics.get("response_latency_seconds")
    if response is None or response > 30:
        recommendations.append("• Practice faster response workflows - aim for sub-30-second containment")
        recommendations.append("• Configure automated playbooks for high-severity alerts")
    
    # Specific technique recommendations
    if not metrics.get("vssadmin_detected"):
        recommendations.append("• Add monitoring for vssadmin.exe and shadow copy deletion (T1490)")
    
    if not metrics.get("persistence_detected"):
        recommendations.append("• Enhance registry monitoring for persistence mechanisms (T1547)")
    
    # File impact recommendations
    if metrics.get("total_files_affected", 0) > 20:
        recommendations.append("• Consider earlier host isolation when file encryption patterns are detected")
        recommendations.append("• Review backup and recovery procedures")
    
    # Study recommendations based on techniques
    if metrics.get("techniques_count", 0) > 0:
        recommendations.append(f"• Study the {metrics['techniques_count']} MITRE ATT&CK techniques observed in this simulation")
    
    # General recommendations
    if run.scenario:
        recommendations.append(f"• Review the '{run.scenario.name}' scenario documentation for expected behaviors")
    
    if not recommendations:
        recommendations.append("• Continue practicing with different scenario types")
        recommendations.append("• Try more aggressive scenarios to test response capabilities")
    
    return "\n".join(recommendations)


def get_feedback_for_run(db: Session, run_id: int) -> Optional[RunFeedback]:
    """Get feedback for a specific run."""
    return db.query(RunFeedback).filter(RunFeedback.run_id == run_id).first()


def get_recent_feedback_for_user(db: Session, user_id: int, limit: int = 5) -> List[RunFeedback]:
    """Get recent feedback for a user."""
    return db.query(RunFeedback).filter(
        RunFeedback.user_id == user_id
    ).order_by(RunFeedback.created_at.desc()).limit(limit).all()
