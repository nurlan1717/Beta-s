"""
Behavior DNA Lab - Behavior Fingerprint Generation Service
===========================================================
Generates behavior profiles for simulation runs including:
- MITRE techniques used
- Action sequences
- Intensity and stealthiness scores
- DNA vector fingerprint
- Profile labels
"""

from datetime import datetime
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from ..models import (
    Run, RunEvent, Alert, Task, AffectedFile, Metric,
    BehaviorProfile, ProfileLabel, EventType,
    MITRE_MAPPING, EVENT_TO_MITRE
)


def generate_behavior_profile(db: Session, run: Run) -> BehaviorProfile:
    """
    Generate a behavior fingerprint for a completed run.
    
    Args:
        db: Database session
        run: The Run object to analyze
        
    Returns:
        BehaviorProfile object (created or updated)
    """
    # Check if profile already exists
    existing = db.query(BehaviorProfile).filter(BehaviorProfile.run_id == run.id).first()
    
    # Gather data
    events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.timestamp).all()
    alerts = db.query(Alert).filter(Alert.run_id == run.id).order_by(Alert.timestamp).all()
    tasks = db.query(Task).filter(Task.run_id == run.id).all()
    affected_files = db.query(AffectedFile).filter(AffectedFile.run_id == run.id).all()
    metrics = db.query(Metric).filter(Metric.run_id == run.id).all()
    
    # Extract techniques
    techniques = _extract_techniques(events, alerts, run)
    
    # Build action sequence
    actions_sequence = _build_action_sequence(events, alerts, tasks, run)
    
    # Calculate intensity score (0-100)
    intensity_score = _calculate_intensity(run, events, affected_files, metrics)
    
    # Calculate stealthiness score (0-100)
    stealthiness_score = _calculate_stealthiness(run, events, alerts)
    
    # Generate DNA vector
    dna_vector = _generate_dna_vector(run, events, alerts, techniques)
    
    # Determine profile label
    profile_label = _determine_profile_label(run, dna_vector, intensity_score, stealthiness_score)
    
    if existing:
        # Update existing profile
        existing.techniques = techniques
        existing.actions_sequence = actions_sequence
        existing.intensity_score = intensity_score
        existing.stealthiness_score = stealthiness_score
        existing.dna_vector = dna_vector
        existing.profile_label = profile_label
        db.commit()
        return existing
    else:
        # Create new profile
        profile = BehaviorProfile(
            run_id=run.id,
            host_id=run.host_id,
            techniques=techniques,
            actions_sequence=actions_sequence,
            intensity_score=intensity_score,
            stealthiness_score=stealthiness_score,
            dna_vector=dna_vector,
            profile_label=profile_label
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile


def _extract_techniques(events: List[RunEvent], alerts: List[Alert], run: Run) -> List[Dict]:
    """Extract MITRE techniques from events and alerts."""
    techniques = {}
    
    # From alerts using MITRE_MAPPING
    for alert in alerts:
        if alert.rule_id in MITRE_MAPPING:
            tech = MITRE_MAPPING[alert.rule_id]
            techniques[tech["technique"]] = {
                "id": tech["technique"],
                "name": tech["name"],
                "source": "alert",
                "rule_id": alert.rule_id
            }
    
    # From events using EVENT_TO_MITRE
    for event in events:
        event_type = event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type)
        if event_type in EVENT_TO_MITRE:
            tech = EVENT_TO_MITRE[event_type]
            if tech["technique"] not in techniques:
                techniques[tech["technique"]] = {
                    "id": tech["technique"],
                    "name": tech["name"],
                    "source": "event",
                    "event_type": event_type
                }
    
    # From scenario tags if available
    if run.scenario and run.scenario.config:
        tags = run.scenario.config.get("tags", [])
        for tag in tags:
            if tag.startswith("MITRE:"):
                tech_id = tag.replace("MITRE:", "")
                if tech_id not in techniques:
                    techniques[tech_id] = {
                        "id": tech_id,
                        "name": _get_technique_name(tech_id),
                        "source": "scenario_tag"
                    }
    
    return list(techniques.values())


def _get_technique_name(tech_id: str) -> str:
    """Get technique name from ID."""
    technique_names = {
        "T1486": "Data Encrypted for Impact",
        "T1490": "Inhibit System Recovery",
        "T1491": "Defacement",
        "T1547": "Boot or Logon Autostart Execution",
        "T1560": "Archive Collected Data",
        "T1485": "Data Destruction",
        "T1041": "Exfiltration Over C2 Channel",
        "T1059": "Command and Scripting Interpreter",
    }
    return technique_names.get(tech_id, "Unknown Technique")


def _build_action_sequence(
    events: List[RunEvent], 
    alerts: List[Alert], 
    tasks: List[Task],
    run: Run
) -> List[Dict]:
    """Build ordered sequence of key actions."""
    sequence = []
    
    # Add run start
    if run.started_at:
        sequence.append({
            "t": run.started_at.isoformat(),
            "type": "SIMULATION_STARTED",
            "details": f"Scenario: {run.scenario.name if run.scenario else 'Unknown'}"
        })
    
    # Add key events (simplified)
    key_event_types = [
        EventType.VSSADMIN_EXECUTED,
        EventType.FILE_RENAMED,
        EventType.FILE_QUARANTINED,
        EventType.RANSOM_NOTE_CREATED,
        EventType.PERSISTENCE_CREATED,
        EventType.EXFIL_PREPARED,
        EventType.PLAYBOOK_TRIGGERED,
        EventType.RESPONSE_EXECUTED
    ]
    
    for event in events:
        if event.event_type in key_event_types:
            sequence.append({
                "t": event.timestamp.isoformat() if event.timestamp else None,
                "type": event.event_type.value,
                "details": str(event.details)[:100] if event.details else None
            })
    
    # Add alerts
    for alert in alerts:
        sequence.append({
            "t": alert.timestamp.isoformat() if alert.timestamp else None,
            "type": f"ALERT_RECEIVED:{alert.rule_id}",
            "details": alert.rule_description
        })
    
    # Add response tasks
    for task in tasks:
        if task.type.startswith("response_") and task.completed_at:
            sequence.append({
                "t": task.completed_at.isoformat(),
                "type": "RESPONSE_ACTION",
                "details": task.type
            })
    
    # Sort by timestamp
    sequence.sort(key=lambda x: x["t"] if x["t"] else "")
    
    # Add run end
    if run.ended_at:
        sequence.append({
            "t": run.ended_at.isoformat(),
            "type": "SIMULATION_ENDED",
            "details": f"Status: {run.status.value}"
        })
    
    return sequence


def _calculate_intensity(
    run: Run, 
    events: List[RunEvent], 
    affected_files: List[AffectedFile],
    metrics: List[Metric]
) -> float:
    """
    Calculate intensity score (0-100).
    
    Based on:
    - Number of files affected
    - Speed of operations
    - Scenario intensity level
    - Number of destructive events
    """
    score = 0.0
    
    # Files affected (max 40 points)
    file_count = len(affected_files)
    score += min(40, file_count * 2)
    
    # Scenario intensity level (max 25 points)
    if run.scenario and run.scenario.config:
        intensity_level = run.scenario.config.get("intensity_level", 2)
        score += intensity_level * 5
    
    # Destructive events (max 20 points)
    destructive_events = [
        EventType.VSSADMIN_EXECUTED,
        EventType.FILE_QUARANTINED,
        EventType.PERSISTENCE_CREATED
    ]
    destructive_count = sum(1 for e in events if e.event_type in destructive_events)
    score += min(20, destructive_count * 5)
    
    # Speed factor from metrics (max 15 points)
    for metric in metrics:
        if metric.name == "execution_time_ms":
            # Faster = more intense
            if metric.value < 5000:  # < 5 seconds
                score += 15
            elif metric.value < 15000:  # < 15 seconds
                score += 10
            elif metric.value < 30000:  # < 30 seconds
                score += 5
    
    return min(100, score)


def _calculate_stealthiness(
    run: Run, 
    events: List[RunEvent], 
    alerts: List[Alert]
) -> float:
    """
    Calculate stealthiness score (0-100).
    
    Based on:
    - Time from first suspicious activity to first alert
    - Ratio of actions to alerts
    - Whether attack completed before detection
    """
    if not run.started_at:
        return 50.0  # Default
    
    score = 50.0  # Start at neutral
    
    # Find first suspicious event
    suspicious_events = [
        EventType.VSSADMIN_EXECUTED,
        EventType.FILE_RENAMED,
        EventType.FILE_QUARANTINED,
        EventType.PERSISTENCE_CREATED
    ]
    
    first_suspicious = None
    for event in events:
        if event.event_type in suspicious_events:
            first_suspicious = event.timestamp
            break
    
    # Find first alert
    first_alert = alerts[0].timestamp if alerts else None
    
    if first_suspicious and first_alert:
        # Calculate detection delay
        delay_seconds = (first_alert - first_suspicious).total_seconds()
        
        if delay_seconds > 60:
            score += 30  # Very stealthy - over 1 minute undetected
        elif delay_seconds > 30:
            score += 20
        elif delay_seconds > 10:
            score += 10
        elif delay_seconds < 5:
            score -= 20  # Detected quickly
    elif not alerts:
        # No alerts = very stealthy (or no detection)
        score += 40
    
    # Actions to alerts ratio
    action_count = len(events)
    alert_count = len(alerts)
    
    if action_count > 0 and alert_count > 0:
        ratio = action_count / alert_count
        if ratio > 5:
            score += 10  # Many actions per alert = stealthy
        elif ratio < 1:
            score -= 10  # More alerts than actions = loud
    
    return max(0, min(100, score))


def _generate_dna_vector(
    run: Run, 
    events: List[RunEvent], 
    alerts: List[Alert],
    techniques: List[Dict]
) -> Dict[str, float]:
    """
    Generate compact DNA vector fingerprint.
    
    Categories:
    - encryption: file encryption/rename activity
    - recovery_inhibition: shadow copy deletion, backup destruction
    - exfil: data exfiltration preparation
    - persistence: registry/scheduled task persistence
    - lateral: lateral movement (future)
    - impact: overall impact level
    """
    vector = {
        "encryption": 0.0,
        "recovery_inhibition": 0.0,
        "exfil": 0.0,
        "persistence": 0.0,
        "lateral": 0.0,
        "impact": 0.0
    }
    
    # Check scenario category
    if run.scenario:
        category = run.scenario.category.value if run.scenario.category else "crypto"
        if category == "crypto":
            vector["encryption"] = 0.8
        elif category == "wiper":
            vector["encryption"] = 0.6
            vector["impact"] = 0.9
        elif category == "exfil":
            vector["exfil"] = 0.8
        elif category == "locker":
            vector["encryption"] = 0.3
            vector["impact"] = 0.5
    
    # Analyze events
    for event in events:
        if event.event_type == EventType.VSSADMIN_EXECUTED:
            vector["recovery_inhibition"] = max(vector["recovery_inhibition"], 0.9)
        elif event.event_type in [EventType.FILE_RENAMED, EventType.FILE_QUARANTINED]:
            vector["encryption"] = max(vector["encryption"], 0.7)
        elif event.event_type == EventType.PERSISTENCE_CREATED:
            vector["persistence"] = max(vector["persistence"], 0.8)
        elif event.event_type == EventType.EXFIL_PREPARED:
            vector["exfil"] = max(vector["exfil"], 0.7)
    
    # Analyze techniques
    for tech in techniques:
        tech_id = tech.get("id", "")
        if tech_id == "T1486":
            vector["encryption"] = max(vector["encryption"], 0.8)
        elif tech_id == "T1490":
            vector["recovery_inhibition"] = max(vector["recovery_inhibition"], 0.9)
        elif tech_id == "T1547":
            vector["persistence"] = max(vector["persistence"], 0.7)
        elif tech_id in ["T1560", "T1041"]:
            vector["exfil"] = max(vector["exfil"], 0.6)
    
    # Calculate overall impact
    vector["impact"] = (
        vector["encryption"] * 0.3 +
        vector["recovery_inhibition"] * 0.3 +
        vector["exfil"] * 0.2 +
        vector["persistence"] * 0.1 +
        vector["lateral"] * 0.1
    )
    
    # Round values
    return {k: round(v, 2) for k, v in vector.items()}


def _determine_profile_label(
    run: Run, 
    dna_vector: Dict[str, float],
    intensity: float,
    stealthiness: float
) -> ProfileLabel:
    """Determine human-readable profile label."""
    
    # Check scenario category first
    if run.scenario:
        category = run.scenario.category.value if run.scenario.category else "crypto"
        
        if category == "fake":
            return ProfileLabel.TRAINING_ONLY
        elif category == "multi-stage":
            return ProfileLabel.MULTI_STAGE
        elif category == "locker":
            return ProfileLabel.LOCKER_STYLE
        elif category == "wiper":
            return ProfileLabel.WIPER_STYLE
        elif category == "exfil":
            return ProfileLabel.EXFIL_FOCUSED
    
    # Determine crypto style based on intensity/stealthiness
    if dna_vector.get("encryption", 0) > 0.5:
        if stealthiness > 60:
            return ProfileLabel.STEALTH_CRYPTO
        else:
            return ProfileLabel.LOUD_CRYPTO
    
    if dna_vector.get("exfil", 0) > 0.5:
        return ProfileLabel.EXFIL_FOCUSED
    
    # Default
    return ProfileLabel.LOUD_CRYPTO


def get_all_behavior_profiles(db: Session, limit: int = 100) -> List[BehaviorProfile]:
    """Get all behavior profiles for the DNA Lab listing."""
    return db.query(BehaviorProfile).order_by(BehaviorProfile.created_at.desc()).limit(limit).all()


def get_behavior_profile_by_run(db: Session, run_id: int) -> Optional[BehaviorProfile]:
    """Get behavior profile for a specific run."""
    return db.query(BehaviorProfile).filter(BehaviorProfile.run_id == run_id).first()
