"""Web UI routes for RANSOMRUN."""

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import MITRE_MAPPING, AuthUser
from ..deps.auth import require_user
from .. import crud

router = APIRouter(tags=["ui"])

templates = Jinja2Templates(directory="app/templates")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Dashboard home page (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    hosts = crud.get_all_hosts(db)
    total_hosts = len(hosts)
    total_runs = crud.count_runs(db)
    successful_runs = crud.count_successful_runs(db)
    recent_alerts = crud.get_all_alerts(db, limit=10)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "total_hosts": total_hosts,
        "total_runs": total_runs,
        "successful_runs": successful_runs,
        "recent_alerts": recent_alerts,
        "mitre_mapping": MITRE_MAPPING
    })


@router.get("/hosts", response_class=HTMLResponse)
def hosts_list(request: Request, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Hosts list page (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    hosts = crud.get_all_hosts(db)
    return templates.TemplateResponse("hosts.html", {
        "request": request,
        "user": user,
        "hosts": hosts
    })


@router.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_detail(request: Request, host_id: int, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Host detail page (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    host = crud.get_host_by_id(db, host_id)
    if not host:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "user": user,
            "error": "Host not found"
        }, status_code=404)
    
    runs = crud.get_runs_by_host(db, host_id)
    alerts = crud.get_alerts_by_host(db, host_id)
    
    return templates.TemplateResponse("host_detail.html", {
        "request": request,
        "user": user,
        "host": host,
        "runs": runs,
        "alerts": alerts[:20]  # Last 20 alerts
    })


@router.get("/scenarios", response_class=HTMLResponse)
def scenarios_list(request: Request, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Scenarios list page with custom scenario support (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    scenarios = crud.get_all_scenarios(db)
    return templates.TemplateResponse("scenarios.html", {
        "request": request,
        "user": user,
        "scenarios": scenarios
    })


@router.get("/scenarios/new", response_class=HTMLResponse)
def scenario_create_form(request: Request, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Create new custom scenario form (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    return templates.TemplateResponse("scenario_form.html", {
        "request": request,
        "user": user,
        "scenario": None,
        "config": None
    })


@router.get("/scenarios/{scenario_id}", response_class=HTMLResponse)
def scenario_detail(request: Request, scenario_id: int, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Scenario detail page (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    scenario = crud.get_scenario_by_id(db, scenario_id)
    if not scenario:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "user": user,
            "error": "Scenario not found"
        }, status_code=404)
    
    # Get runs using this scenario
    from ..models import Run
    runs = db.query(Run).filter(Run.scenario_id == scenario_id).order_by(Run.id.desc()).limit(10).all()
    
    return templates.TemplateResponse("scenario_detail.html", {
        "request": request,
        "scenario": scenario,
        "config": scenario.config,
        "runs": runs
    })


@router.get("/scenarios/{scenario_id}/edit", response_class=HTMLResponse)
def scenario_edit_form(request: Request, scenario_id: int, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Edit custom scenario form (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    scenario = crud.get_scenario_by_id(db, scenario_id)
    if not scenario:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "user": user,
            "error": "Scenario not found"
        }, status_code=404)
    
    if not scenario.is_custom:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "user": user,
            "error": "Built-in scenarios cannot be edited. Clone it to create a custom version."
        }, status_code=403)
    
    return templates.TemplateResponse("scenario_form.html", {
        "request": request,
        "user": user,
        "scenario": scenario,
        "config": scenario.config
    })


@router.get("/runs", response_class=HTMLResponse)
def runs_list(request: Request, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Runs list page (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    runs = crud.get_all_runs(db)
    return templates.TemplateResponse("runs.html", {
        "request": request,
        "user": user,
        "runs": runs
    })


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: int, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Run detail / Incident report page with timeline and advanced features (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    from ..models import BehaviorProfile, RunFeedback, BusinessImpact, ComplianceReport, WhatIfScenario
    
    run = crud.get_run_by_id(db, run_id)
    if not run:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Run not found"
        }, status_code=404)
    
    tasks = crud.get_tasks_by_run(db, run_id)
    alerts = crud.get_alerts_by_run(db, run_id)
    events = crud.get_events_by_run(db, run_id)
    metrics = crud.get_metrics_by_run(db, run_id)
    iocs = crud.get_iocs_by_run(db, run_id)
    affected_files_count = crud.count_affected_files_by_run(db, run_id)
    
    # Build unified timeline
    timeline = build_timeline(run, tasks, alerts, events)
    
    # Generate summary
    summary = generate_run_summary(run, tasks, alerts)
    summary["files_affected"] = affected_files_count
    summary["iocs_count"] = len(iocs)
    
    # Convert metrics to dict
    metrics_dict = {m.name: m.value for m in metrics}
    
    # Get advanced features data
    behavior_profile = db.query(BehaviorProfile).filter(BehaviorProfile.run_id == run_id).first()
    feedback = db.query(RunFeedback).filter(RunFeedback.run_id == run_id).first()
    business_impact = db.query(BusinessImpact).filter(BusinessImpact.run_id == run_id).first()
    compliance_report = db.query(ComplianceReport).filter(ComplianceReport.run_id == run_id).first()
    whatif_scenarios = db.query(WhatIfScenario).filter(WhatIfScenario.run_id == run_id).all()
    
    return templates.TemplateResponse("run_detail.html", {
        "request": request,
        "user": user,
        "run": run,
        "tasks": tasks,
        "alerts": alerts,
        "events": events,
        "timeline": timeline,
        "metrics": metrics_dict,
        "iocs": iocs,
        "summary": summary,
        "mitre_mapping": MITRE_MAPPING,
        "behavior_profile": behavior_profile,
        "feedback": feedback,
        "business_impact": business_impact,
        "compliance_report": compliance_report,
        "whatif_scenarios": whatif_scenarios
    })


@router.get("/simulate", response_class=HTMLResponse)
def simulate_form(request: Request, user: AuthUser = Depends(require_user), db: Session = Depends(get_db)):
    """Start simulation form page (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    hosts = crud.get_all_hosts(db)
    scenarios = crud.get_all_scenarios(db)
    return templates.TemplateResponse("simulate.html", {
        "request": request,
        "user": user,
        "hosts": hosts,
        "scenarios": scenarios
    })


@router.post("/simulate", response_class=HTMLResponse)
def start_simulation(
    request: Request,
    host_id: int = Form(...),
    scenario_id: int = Form(...),
    user: AuthUser = Depends(require_user),
    db: Session = Depends(get_db)
):
    """Handle simulation form submission."""
    # Validate host
    host = crud.get_host_by_id(db, host_id)
    if not host:
        return templates.TemplateResponse("simulate.html", {
            "request": request,
            "hosts": crud.get_all_hosts(db),
            "scenarios": crud.get_all_scenarios(db),
            "error": "Host not found"
        })
    
    # Validate scenario
    scenario = crud.get_scenario_by_id(db, scenario_id)
    if not scenario:
        return templates.TemplateResponse("simulate.html", {
            "request": request,
            "hosts": crud.get_all_hosts(db),
            "scenarios": crud.get_all_scenarios(db),
            "error": "Scenario not found"
        })
    
    # Check for active run
    active_run = crud.get_active_run_for_host(db, host.id)
    if active_run:
        return templates.TemplateResponse("simulate.html", {
            "request": request,
            "hosts": crud.get_all_hosts(db),
            "scenarios": crud.get_all_scenarios(db),
            "error": f"Host already has an active run (ID: {active_run.id})"
        })
    
    # Create run and task with scenario config
    from ..models import EventType
    
    run = crud.create_run(db, host_id=host.id, scenario_id=scenario.id)
    
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
    crud.create_run_event(db, run.id, EventType.RUN_CREATED, host.id, {
        "scenario_key": scenario.key,
        "scenario_name": scenario.name
    })
    
    # Redirect to run detail
    return RedirectResponse(url=f"/runs/{run.id}", status_code=303)


@router.get("/playbooks", response_class=HTMLResponse)
def playbooks_list(request: Request, db: Session = Depends(get_db)):
    """Playbooks list page."""
    playbooks = crud.get_all_playbooks(db)
    return templates.TemplateResponse("playbooks.html", {
        "request": request,
        "playbooks": playbooks,
        "mitre_mapping": MITRE_MAPPING
    })


@router.get("/alerts", response_class=HTMLResponse)
def alerts_list(request: Request, db: Session = Depends(get_db)):
    """Alerts list page."""
    alerts = crud.get_all_alerts(db, limit=100)
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts,
        "mitre_mapping": MITRE_MAPPING
    })


def generate_run_summary(run, tasks, alerts) -> dict:
    """Generate a summary for a run."""
    total_tasks = len(tasks)
    completed_tasks = sum(1 for t in tasks if t.status.value == "COMPLETED")
    failed_tasks = sum(1 for t in tasks if t.status.value == "FAILED")
    
    simulation_tasks = [t for t in tasks if t.type == "simulate_ransomware"]
    response_tasks = [t for t in tasks if t.type.startswith("response_")]
    
    # Determine overall outcome
    if run.status.value == "COMPLETED":
        outcome = "Simulation completed successfully"
    elif run.status.value == "FAILED":
        outcome = "Simulation failed or was interrupted"
    elif run.status.value == "RUNNING":
        outcome = "Simulation in progress"
    else:
        outcome = "Simulation pending"
    
    # Calculate duration
    duration = None
    if run.started_at and run.ended_at:
        delta = run.ended_at - run.started_at
        duration = str(delta).split('.')[0]  # Remove microseconds
    
    return {
        "outcome": outcome,
        "duration": duration,
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "failed_tasks": failed_tasks,
        "simulation_tasks": len(simulation_tasks),
        "response_tasks": len(response_tasks),
        "total_alerts": len(alerts),
        "high_severity_alerts": sum(1 for a in alerts if a.severity >= 10)
    }


def build_timeline(run, tasks, alerts, events) -> list:
    """Build a unified timeline from all run events."""
    timeline = []
    
    # Add run creation
    if run.started_at:
        timeline.append({
            "timestamp": run.started_at,
            "type": "run",
            "icon": "play-circle",
            "color": "info",
            "title": "Simulation Started",
            "description": f"Run #{run.id} initiated"
        })
    
    # Add events from RunEvent table
    for event in events:
        event_config = {
            "RUN_CREATED": ("flag", "info", "Run Created"),
            "TASK_ASSIGNED": ("list-task", "secondary", "Task Assigned"),
            "TASK_SENT": ("send", "info", "Task Sent to Agent"),
            "TASK_STARTED": ("play", "info", "Task Started"),
            "TASK_COMPLETED": ("check-circle", "success", "Task Completed"),
            "TASK_FAILED": ("x-circle", "danger", "Task Failed"),
            "FILE_RENAMED": ("file-earmark", "warning", "Files Renamed"),
            "FILE_QUARANTINED": ("folder-minus", "warning", "Files Quarantined"),
            "RANSOM_NOTE_CREATED": ("file-text", "danger", "Ransom Note Created"),
            "VSSADMIN_EXECUTED": ("trash", "danger", "Shadow Copies Deleted"),
            "PERSISTENCE_CREATED": ("key", "warning", "Persistence Established"),
            "EXFIL_PREPARED": ("cloud-upload", "warning", "Exfiltration Prepared"),
            "ALERT_RECEIVED": ("bell", "danger", "Alert Received"),
            "PLAYBOOK_TRIGGERED": ("journal-code", "purple", "Playbook Triggered"),
            "RESPONSE_TASK_CREATED": ("shield", "info", "Response Task Created"),
            "RESPONSE_EXECUTED": ("shield-check", "success", "Response Executed"),
            "RUN_COMPLETED": ("check-circle-fill", "success", "Run Completed"),
            "RUN_FAILED": ("x-circle-fill", "danger", "Run Failed"),
        }
        
        config = event_config.get(event.event_type.value, ("circle", "secondary", event.event_type.value))
        
        timeline.append({
            "timestamp": event.timestamp,
            "type": "event",
            "icon": config[0],
            "color": config[1],
            "title": config[2],
            "description": str(event.details) if event.details else None
        })
    
    # Add alerts
    for alert in alerts:
        timeline.append({
            "timestamp": alert.timestamp,
            "type": "alert",
            "icon": "exclamation-triangle",
            "color": "danger" if alert.severity >= 10 else "warning",
            "title": f"Alert: {alert.rule_id}",
            "description": alert.rule_description
        })
    
    # Add task completions
    for task in tasks:
        if task.completed_at:
            timeline.append({
                "timestamp": task.completed_at,
                "type": "task",
                "icon": "check" if task.status.value == "COMPLETED" else "x",
                "color": "success" if task.status.value == "COMPLETED" else "danger",
                "title": f"Task: {task.type}",
                "description": task.result_message[:100] if task.result_message else None
            })
    
    # Add run end
    if run.ended_at:
        timeline.append({
            "timestamp": run.ended_at,
            "type": "run",
            "icon": "stop-circle",
            "color": "success" if run.status.value == "COMPLETED" else "danger",
            "title": "Simulation Ended",
            "description": f"Status: {run.status.value}"
        })
    
    # Sort by timestamp
    timeline.sort(key=lambda x: x["timestamp"] if x["timestamp"] else run.started_at or run.ended_at)
    
    return timeline


# ============ SIEM UI Routes ============

@router.get("/siem", response_class=HTMLResponse)
def siem_overview(request: Request, db: Session = Depends(get_db)):
    """SIEM overview page."""
    stats = crud.get_alert_stats(db, hours=24)
    alerts_over_time = crud.get_alerts_over_time(db, hours=24)
    recent_alerts = crud.get_all_alerts(db, limit=20)
    elk_config = crud.get_elk_config(db)
    
    return templates.TemplateResponse("siem_overview.html", {
        "request": request,
        "stats": stats,
        "alerts_over_time": alerts_over_time,
        "recent_alerts": recent_alerts,
        "elk_config": elk_config,
        "mitre_mapping": MITRE_MAPPING
    })


@router.get("/siem/explorer", response_class=HTMLResponse)
def siem_explorer(request: Request, db: Session = Depends(get_db)):
    """SIEM alerts explorer page."""
    alerts = crud.get_all_alerts(db, limit=200)
    hosts = crud.get_all_hosts(db)
    
    # Get unique rule IDs for filter
    rule_ids = list(set(a.rule_id for a in alerts))
    
    return templates.TemplateResponse("siem_explorer.html", {
        "request": request,
        "alerts": alerts,
        "hosts": hosts,
        "rule_ids": rule_ids,
        "mitre_mapping": MITRE_MAPPING
    })


@router.get("/siem/alerts/{alert_id}", response_class=HTMLResponse)
def siem_alert_detail(request: Request, alert_id: int, db: Session = Depends(get_db)):
    """SIEM alert detail page."""
    alert = crud.get_alert_by_id(db, alert_id)
    if not alert:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Alert not found"
        }, status_code=404)
    
    return templates.TemplateResponse("siem_alert_detail.html", {
        "request": request,
        "alert": alert,
        "mitre_mapping": MITRE_MAPPING
    })


@router.get("/siem/elk", response_class=HTMLResponse)
def elk_dashboard(request: Request, db: Session = Depends(get_db)):
    """ELK SIEM Dashboard page."""
    return templates.TemplateResponse("elk_dashboard.html", {
        "request": request
    })


# =============================================================================
# ADVANCED FEATURES PAGES
# =============================================================================

@router.get("/dna-lab", response_class=HTMLResponse)
def dna_lab(request: Request, db: Session = Depends(get_db)):
    """Behavior DNA Lab page."""
    from ..models import BehaviorProfile, ProfileLabel
    
    profiles = db.query(BehaviorProfile).order_by(BehaviorProfile.created_at.desc()).limit(100).all()
    
    # Calculate stats
    loud_count = sum(1 for p in profiles if p.profile_label and 'LOUD' in p.profile_label.value)
    stealth_count = sum(1 for p in profiles if p.profile_label and 'STEALTH' in p.profile_label.value)
    avg_intensity = sum(p.intensity_score for p in profiles) / len(profiles) if profiles else 0
    
    return templates.TemplateResponse("dna_lab.html", {
        "request": request,
        "profiles": profiles,
        "loud_count": loud_count,
        "stealth_count": stealth_count,
        "avg_intensity": avg_intensity
    })


@router.get("/users", response_class=HTMLResponse)
def users_list(request: Request, db: Session = Depends(get_db)):
    """Analysts list page."""
    from ..models import User, IRSession
    
    users = db.query(User).all()
    
    # Get session counts for each user
    user_stats = []
    for user in users:
        session_count = db.query(IRSession).filter(IRSession.user_id == user.id).count()
        user_stats.append({
            "user": user,
            "sessions": session_count
        })
    
    return templates.TemplateResponse("users.html", {
        "request": request,
        "user_stats": user_stats
    })


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(request: Request, user_id: int, db: Session = Depends(get_db)):
    """User profile / SOC CV page."""
    from ..models import User, IRSession, RunFeedback, UserSkillProfile
    
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": "User not found"
            }, status_code=404)
        
        # Safely query related data
        sessions = []
        feedbacks = []
        skill_profile = None
        
        try:
            sessions = db.query(IRSession).filter(IRSession.user_id == user_id).all()
        except Exception:
            pass
        
        try:
            feedbacks = db.query(RunFeedback).filter(RunFeedback.user_id == user_id).order_by(RunFeedback.created_at.desc()).limit(5).all()
        except Exception:
            pass
        
        try:
            skill_profile = db.query(UserSkillProfile).filter(UserSkillProfile.user_id == user_id).first()
        except Exception:
            pass
        
        return templates.TemplateResponse("user_detail.html", {
            "request": request,
            "user": user,
            "sessions": sessions,
            "feedbacks": feedbacks,
            "skill_profile": skill_profile
        })
    except Exception as e:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": f"Error loading user profile: {str(e)}"
        }, status_code=500)


@router.get("/runs/{run_id}/compliance", response_class=HTMLResponse)
def compliance_report_page(request: Request, run_id: int, db: Session = Depends(get_db)):
    """Full compliance report page."""
    from ..models import ComplianceReport
    
    run = crud.get_run_by_id(db, run_id)
    if not run:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Run not found"
        }, status_code=404)
    
    report = db.query(ComplianceReport).filter(ComplianceReport.run_id == run_id).first()
    
    return templates.TemplateResponse("compliance_report.html", {
        "request": request,
        "run": run,
        "report": report
    })


@router.get("/environment", response_class=HTMLResponse)
def environment_page(
    request: Request,
    user: AuthUser = Depends(require_user), 
    db: Session = Depends(get_db)
):
    """Directory Lab / Environment Management page (protected)."""
    if isinstance(user, RedirectResponse):
        return user
    
    return templates.TemplateResponse("environment.html", {
        "request": request,
        "user": user
    })
