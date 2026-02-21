"""
What-If Time Machine - Counterfactual Defense Analysis Service
===============================================================
Allows users to simulate how outcomes would change with different
defensive conditions, without re-running the attack.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
from sqlalchemy.orm import Session

from ..models import (
    Run, RunEvent, Alert, Task, AffectedFile, WhatIfScenario, EventType
)


# Predefined What-If scenario templates
WHATIF_TEMPLATES = {
    "extra_powershell_rule": {
        "name": "Extra Wazuh Rule for PowerShell",
        "description": "What if we had a rule detecting encoded PowerShell commands?",
        "assumptions": {
            "detection_threshold": "lower",
            "extra_rules": ["100106"],
            "early_detection_events": ["PERSISTENCE_CREATED"],
            "detection_improvement_seconds": 15
        }
    },
    "edr_present": {
        "name": "EDR Agent Present",
        "description": "What if an EDR solution was monitoring the endpoint?",
        "assumptions": {
            "edr_present": True,
            "process_kill_delay_seconds": 5,
            "detection_improvement_seconds": 20,
            "file_impact_reduction_percent": 60
        }
    },
    "no_local_admin": {
        "name": "User Not Local Admin",
        "description": "What if the compromised user didn't have local admin rights?",
        "assumptions": {
            "user_is_admin": False,
            "blocked_actions": ["VSSADMIN_EXECUTED", "PERSISTENCE_CREATED"],
            "file_impact_reduction_percent": 30
        }
    },
    "faster_response": {
        "name": "Faster SOC Response",
        "description": "What if the SOC responded within 30 seconds of first alert?",
        "assumptions": {
            "response_time_seconds": 30,
            "immediate_isolation": True,
            "file_impact_reduction_percent": 70
        }
    },
    "backup_available": {
        "name": "Recent Backups Available",
        "description": "What if we had backups from the last hour?",
        "assumptions": {
            "backup_age_hours": 1,
            "recovery_time_reduction_percent": 80,
            "data_loss_reduction_percent": 95
        }
    }
}


def create_whatif_scenario(
    db: Session, 
    run: Run, 
    template_key: str
) -> WhatIfScenario:
    """
    Create a What-If scenario for a run using a predefined template.
    
    Args:
        db: Database session
        run: The Run to analyze
        template_key: Key from WHATIF_TEMPLATES
        
    Returns:
        WhatIfScenario with recalculated metrics
    """
    if template_key not in WHATIF_TEMPLATES:
        raise ValueError(f"Unknown template: {template_key}")
    
    template = WHATIF_TEMPLATES[template_key]
    assumptions = template["assumptions"]
    
    # Gather original data
    events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.timestamp).all()
    alerts = db.query(Alert).filter(Alert.run_id == run.id).order_by(Alert.timestamp).all()
    affected_files = db.query(AffectedFile).filter(AffectedFile.run_id == run.id).all()
    
    # Calculate original metrics
    original_metrics = _calculate_original_metrics(run, events, alerts, affected_files)
    
    # Recalculate under new assumptions
    recalculated = _recalculate_metrics(original_metrics, assumptions, events, alerts)
    
    # Create scenario
    scenario = WhatIfScenario(
        run_id=run.id,
        name=template["name"],
        assumptions=assumptions,
        recalculated_metrics=recalculated
    )
    
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    
    return scenario


def create_custom_whatif(
    db: Session,
    run: Run,
    name: str,
    assumptions: Dict
) -> WhatIfScenario:
    """Create a custom What-If scenario with user-defined assumptions."""
    events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.timestamp).all()
    alerts = db.query(Alert).filter(Alert.run_id == run.id).order_by(Alert.timestamp).all()
    affected_files = db.query(AffectedFile).filter(AffectedFile.run_id == run.id).all()
    
    original_metrics = _calculate_original_metrics(run, events, alerts, affected_files)
    recalculated = _recalculate_metrics(original_metrics, assumptions, events, alerts)
    
    scenario = WhatIfScenario(
        run_id=run.id,
        name=name,
        assumptions=assumptions,
        recalculated_metrics=recalculated
    )
    
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    
    return scenario


def _calculate_original_metrics(
    run: Run,
    events: List[RunEvent],
    alerts: List[Alert],
    affected_files: List[AffectedFile]
) -> Dict:
    """Calculate original metrics from the actual run."""
    metrics = {
        "detection_time_seconds": None,
        "response_time_seconds": None,
        "files_impacted": len(affected_files),
        "total_alerts": len(alerts),
        "containment_time_seconds": None,
        "risk_score": 50  # Default
    }
    
    if not run.started_at:
        return metrics
    
    # Time to first detection (first alert)
    if alerts:
        first_alert = alerts[0]
        if first_alert.timestamp:
            metrics["detection_time_seconds"] = (
                first_alert.timestamp - run.started_at
            ).total_seconds()
    
    # Time to first response action
    response_events = [e for e in events if e.event_type == EventType.RESPONSE_EXECUTED]
    if response_events:
        first_response = response_events[0]
        if first_response.timestamp:
            metrics["response_time_seconds"] = (
                first_response.timestamp - run.started_at
            ).total_seconds()
    
    # Containment time (run end or isolation event)
    if run.ended_at:
        metrics["containment_time_seconds"] = (
            run.ended_at - run.started_at
        ).total_seconds()
    
    # Calculate risk score based on impact
    risk = 30  # Base
    risk += min(30, len(affected_files) * 2)  # Files impact
    risk += min(20, len(alerts) * 3)  # Alert severity proxy
    
    # Check for high-impact events
    high_impact_events = [EventType.VSSADMIN_EXECUTED, EventType.PERSISTENCE_CREATED]
    for event in events:
        if event.event_type in high_impact_events:
            risk += 10
    
    metrics["risk_score"] = min(100, risk)
    
    return metrics


def _recalculate_metrics(
    original: Dict,
    assumptions: Dict,
    events: List[RunEvent],
    alerts: List[Alert]
) -> Dict:
    """
    Recalculate metrics under hypothetical assumptions.
    
    Heuristic rules documented inline.
    """
    new_metrics = original.copy()
    new_metrics["original"] = original.copy()
    new_metrics["improvements"] = []
    
    # --- Detection improvement ---
    detection_improvement = assumptions.get("detection_improvement_seconds", 0)
    if detection_improvement > 0 and original["detection_time_seconds"]:
        new_detection = max(1, original["detection_time_seconds"] - detection_improvement)
        new_metrics["new_detection_time_seconds"] = new_detection
        new_metrics["improvements"].append(
            f"Detection time reduced by {detection_improvement}s"
        )
    else:
        new_metrics["new_detection_time_seconds"] = original["detection_time_seconds"]
    
    # --- Early detection from specific events ---
    early_events = assumptions.get("early_detection_events", [])
    if early_events:
        for event in events:
            event_type = event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type)
            if event_type in early_events:
                # This event would have triggered earlier detection
                if event.timestamp and alerts:
                    first_alert_time = alerts[0].timestamp
                    if event.timestamp < first_alert_time:
                        time_saved = (first_alert_time - event.timestamp).total_seconds()
                        new_metrics["new_detection_time_seconds"] = max(
                            1, 
                            new_metrics["new_detection_time_seconds"] - time_saved
                        )
                        new_metrics["improvements"].append(
                            f"Early detection of {event_type} would save {time_saved:.0f}s"
                        )
                break
    
    # --- EDR present ---
    if assumptions.get("edr_present"):
        # EDR would kill malicious processes faster
        process_kill_delay = assumptions.get("process_kill_delay_seconds", 5)
        new_metrics["new_response_time_seconds"] = process_kill_delay
        new_metrics["improvements"].append(
            f"EDR would respond within {process_kill_delay}s"
        )
    else:
        new_metrics["new_response_time_seconds"] = original["response_time_seconds"]
    
    # --- Faster SOC response ---
    if "response_time_seconds" in assumptions:
        new_metrics["new_response_time_seconds"] = assumptions["response_time_seconds"]
        new_metrics["improvements"].append(
            f"SOC response time set to {assumptions['response_time_seconds']}s"
        )
    
    # --- File impact reduction ---
    file_reduction = assumptions.get("file_impact_reduction_percent", 0)
    if file_reduction > 0:
        new_files = int(original["files_impacted"] * (1 - file_reduction / 100))
        new_metrics["new_files_impacted"] = new_files
        new_metrics["improvements"].append(
            f"Files impacted reduced by {file_reduction}% ({original['files_impacted']} → {new_files})"
        )
    else:
        new_metrics["new_files_impacted"] = original["files_impacted"]
    
    # --- Blocked actions (no local admin) ---
    blocked = assumptions.get("blocked_actions", [])
    if blocked:
        blocked_count = sum(
            1 for e in events 
            if (e.event_type.value if hasattr(e.event_type, 'value') else str(e.event_type)) in blocked
        )
        if blocked_count > 0:
            new_metrics["improvements"].append(
                f"{blocked_count} high-privilege actions would be blocked"
            )
            # Reduce risk score
            new_metrics["new_risk_score"] = max(10, original["risk_score"] - blocked_count * 15)
    
    # --- Calculate new risk score ---
    if "new_risk_score" not in new_metrics:
        risk_reduction = 0
        orig_detection = original.get("detection_time_seconds") or 999
        orig_response = original.get("response_time_seconds") or 999
        new_detection = new_metrics.get("new_detection_time_seconds") or 999
        new_response = new_metrics.get("new_response_time_seconds") or 999
        
        if new_detection < orig_detection:
            risk_reduction += 10
        if new_response < orig_response:
            risk_reduction += 15
        if new_metrics.get("new_files_impacted", 999) < original.get("files_impacted", 0):
            risk_reduction += 20
        
        new_metrics["new_risk_score"] = max(5, original.get("risk_score", 50) - risk_reduction)
    
    # --- Summary ---
    new_metrics["risk_reduction"] = original["risk_score"] - new_metrics["new_risk_score"]
    new_metrics["summary"] = _generate_summary(original, new_metrics, assumptions)
    
    return new_metrics


def _generate_summary(original: Dict, new_metrics: Dict, assumptions: Dict) -> str:
    """Generate human-readable summary of What-If analysis."""
    parts = []
    
    if new_metrics.get("new_detection_time_seconds") and original.get("detection_time_seconds"):
        if new_metrics["new_detection_time_seconds"] < original["detection_time_seconds"]:
            parts.append(
                f"Detection would be {original['detection_time_seconds'] - new_metrics['new_detection_time_seconds']:.0f}s faster"
            )
    
    if new_metrics.get("new_files_impacted", 0) < original.get("files_impacted", 0):
        reduction = original["files_impacted"] - new_metrics["new_files_impacted"]
        parts.append(f"{reduction} fewer files would be affected")
    
    if new_metrics.get("risk_reduction", 0) > 0:
        parts.append(f"Risk score reduced by {new_metrics['risk_reduction']} points")
    
    if not parts:
        return "Minimal impact from these changes."
    
    return ". ".join(parts) + "."


def get_whatif_scenarios_for_run(db: Session, run_id: int) -> List[WhatIfScenario]:
    """Get all What-If scenarios for a run."""
    return db.query(WhatIfScenario).filter(WhatIfScenario.run_id == run_id).all()


def get_whatif_templates() -> Dict:
    """Get available What-If templates."""
    return WHATIF_TEMPLATES
