"""CRUD operations for RANSOMRUN."""

from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from .models import (
    Host, Scenario, Run, Task, Alert, Playbook,
    RunEvent, AffectedFile, Metric, IOC, ELKConfig,
    RecoveryPlan, RecoveryEvent, BusinessImpact, ComplianceReport,
    HostStatus, RunStatus, TaskStatus, EventType, FileActionType, IOCType,
    RecoveryPlanStatus, RecoveryEventType
)


# ============ Host Operations ============

def get_host_by_agent_id(db: Session, agent_id: str) -> Optional[Host]:
    return db.query(Host).filter(Host.agent_id == agent_id).first()


def get_host_by_name(db: Session, name: str) -> Optional[Host]:
    return db.query(Host).filter(Host.name == name).first()


def get_host_by_id(db: Session, host_id: int) -> Optional[Host]:
    return db.query(Host).filter(Host.id == host_id).first()


def get_all_hosts(db: Session) -> List[Host]:
    return db.query(Host).order_by(desc(Host.updated_at)).all()


def create_or_update_host(
    db: Session, 
    agent_id: str, 
    hostname: str, 
    ip_address: Optional[str] = None
) -> Host:
    host = get_host_by_agent_id(db, agent_id)
    if host:
        host.name = hostname
        host.ip_address = ip_address
        host.status = HostStatus.ONLINE
        host.updated_at = datetime.utcnow()
    else:
        host = Host(
            agent_id=agent_id,
            name=hostname,
            ip_address=ip_address,
            status=HostStatus.ONLINE
        )
        db.add(host)
    db.commit()
    db.refresh(host)
    return host


# ============ Scenario Operations ============

def get_scenario_by_id(db: Session, scenario_id: int) -> Optional[Scenario]:
    return db.query(Scenario).filter(Scenario.id == scenario_id).first()


def get_scenario_by_key(db: Session, key: str) -> Optional[Scenario]:
    return db.query(Scenario).filter(Scenario.key == key).first()


def get_all_scenarios(db: Session) -> List[Scenario]:
    return db.query(Scenario).all()


def create_scenario(db: Session, key: str, name: str, description: str) -> Scenario:
    scenario = Scenario(key=key, name=name, description=description)
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


def create_custom_scenario(
    db: Session,
    key: str,
    name: str,
    description: str,
    category: str,
    config: dict,
    created_by: str = "admin"
) -> Scenario:
    """Create a new custom scenario."""
    from .models import ScenarioCategory
    
    # Map category string to enum
    category_map = {
        "crypto": ScenarioCategory.CRYPTO,
        "locker": ScenarioCategory.LOCKER,
        "wiper": ScenarioCategory.WIPER,
        "exfil": ScenarioCategory.EXFIL,
        "fake": ScenarioCategory.FAKE,
        "multi-stage": ScenarioCategory.MULTI_STAGE,
    }
    cat_enum = category_map.get(category.lower(), ScenarioCategory.CRYPTO)
    
    scenario = Scenario(
        key=key,
        name=name,
        description=description,
        category=cat_enum,
        config=config,
        is_custom=True,
        created_by=created_by
    )
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


def update_custom_scenario(
    db: Session,
    scenario_id: int,
    name: Optional[str] = None,
    description: Optional[str] = None,
    category: Optional[str] = None,
    config: Optional[dict] = None
) -> Optional[Scenario]:
    """Update an existing custom scenario. Returns None if not found or not custom."""
    from .models import ScenarioCategory
    
    scenario = get_scenario_by_id(db, scenario_id)
    if not scenario or not scenario.is_custom:
        return None
    
    if name is not None:
        scenario.name = name
    if description is not None:
        scenario.description = description
    if category is not None:
        category_map = {
            "crypto": ScenarioCategory.CRYPTO,
            "locker": ScenarioCategory.LOCKER,
            "wiper": ScenarioCategory.WIPER,
            "exfil": ScenarioCategory.EXFIL,
            "fake": ScenarioCategory.FAKE,
            "multi-stage": ScenarioCategory.MULTI_STAGE,
        }
        scenario.category = category_map.get(category.lower(), ScenarioCategory.CRYPTO)
    if config is not None:
        scenario.config = config
    
    db.commit()
    db.refresh(scenario)
    return scenario


def delete_custom_scenario(db: Session, scenario_id: int) -> bool:
    """Delete a custom scenario. Returns False if not found or not custom."""
    scenario = get_scenario_by_id(db, scenario_id)
    if not scenario or not scenario.is_custom:
        return False
    
    # Check if scenario has associated runs
    if scenario.runs:
        return False  # Cannot delete scenario with runs
    
    db.delete(scenario)
    db.commit()
    return True


def clone_scenario(
    db: Session,
    scenario_id: int,
    new_name: str,
    new_key: str,
    created_by: str = "admin"
) -> Optional[Scenario]:
    """Clone an existing scenario (built-in or custom) into a new custom scenario."""
    source = get_scenario_by_id(db, scenario_id)
    if not source:
        return None
    
    new_scenario = Scenario(
        key=new_key,
        name=new_name,
        description=f"Cloned from: {source.name}\n\n{source.description or ''}",
        category=source.category,
        config=source.config.copy() if source.config else {},
        is_custom=True,
        created_by=created_by
    )
    db.add(new_scenario)
    db.commit()
    db.refresh(new_scenario)
    return new_scenario


def get_custom_scenarios(db: Session) -> List[Scenario]:
    """Get all custom (user-created) scenarios."""
    return db.query(Scenario).filter(Scenario.is_custom == True).all()


def get_builtin_scenarios(db: Session) -> List[Scenario]:
    """Get all built-in scenarios."""
    return db.query(Scenario).filter(Scenario.is_custom == False).all()


def generate_unique_scenario_key(db: Session, base_name: str) -> str:
    """Generate a unique scenario key based on a name."""
    import re
    import uuid
    
    # Convert name to key format
    key_base = re.sub(r'[^a-z0-9]+', '_', base_name.lower()).strip('_')
    if not key_base:
        key_base = "custom"
    
    # Add short unique suffix
    short_id = uuid.uuid4().hex[:8]
    key = f"custom_{key_base}_{short_id}"
    
    # Ensure uniqueness
    while get_scenario_by_key(db, key):
        short_id = uuid.uuid4().hex[:8]
        key = f"custom_{key_base}_{short_id}"
    
    return key


# ============ Run Operations ============

def get_run_by_id(db: Session, run_id: int) -> Optional[Run]:
    return db.query(Run).filter(Run.id == run_id).first()


def get_all_runs(db: Session) -> List[Run]:
    return db.query(Run).order_by(desc(Run.id)).all()


def get_runs_by_host(db: Session, host_id: int) -> List[Run]:
    return db.query(Run).filter(Run.host_id == host_id).order_by(desc(Run.id)).all()


def get_active_run_for_host(db: Session, host_id: int) -> Optional[Run]:
    """Get the most recent active (PENDING or RUNNING) run for a host."""
    return db.query(Run).filter(
        Run.host_id == host_id,
        Run.status.in_([RunStatus.PENDING, RunStatus.RUNNING])
    ).order_by(desc(Run.id)).first()


def create_run(db: Session, host_id: int, scenario_id: int) -> Run:
    run = Run(
        host_id=host_id,
        scenario_id=scenario_id,
        status=RunStatus.PENDING
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def update_run_status(db: Session, run_id: int, status: RunStatus, ended_at: Optional[datetime] = None):
    run = get_run_by_id(db, run_id)
    if run:
        run.status = status
        if status == RunStatus.RUNNING and not run.started_at:
            run.started_at = datetime.utcnow()
        if ended_at:
            run.ended_at = ended_at
        db.commit()


def count_runs(db: Session) -> int:
    return db.query(Run).count()


def count_successful_runs(db: Session) -> int:
    return db.query(Run).filter(Run.status == RunStatus.COMPLETED).count()


def stop_run(db: Session, run_id: int) -> dict:
    """
    Stop a running or pending simulation.
    Returns dict with status and message.
    """
    run = get_run_by_id(db, run_id)
    if not run:
        return {"success": False, "message": "Run not found"}
    
    # Check if run is stoppable
    if run.status in [RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELED]:
        return {"success": False, "message": f"Run not stoppable (status: {run.status.value})"}
    
    # If already stopping, return current state (idempotency)
    if run.status == RunStatus.STOPPING:
        return {"success": True, "message": "Run already stopping", "status": "STOPPING"}
    
    # Handle PENDING runs
    if run.status == RunStatus.PENDING:
        # Cancel any pending tasks
        pending_tasks = db.query(Task).filter(
            Task.run_id == run_id,
            Task.status == TaskStatus.PENDING
        ).all()
        
        for task in pending_tasks:
            db.delete(task)
        
        # Mark run as CANCELED
        run.status = RunStatus.CANCELED
        run.ended_at = datetime.utcnow()
        
        # Create event
        create_run_event(db, run_id, EventType.STOP_REQUESTED, run.host_id, {
            "reason": "Stopped by user",
            "previous_status": "PENDING"
        })
        
        db.commit()
        return {
            "success": True,
            "message": f"Pending run canceled, {len(pending_tasks)} tasks removed",
            "status": "CANCELED"
        }
    
    # Handle RUNNING runs
    if run.status == RunStatus.RUNNING:
        # Check if stop task already exists (idempotency)
        existing_stop_task = db.query(Task).filter(
            Task.run_id == run_id,
            Task.type == "stop_simulation",
            Task.status.in_([TaskStatus.PENDING, TaskStatus.SENT, TaskStatus.RUNNING])
        ).first()
        
        if existing_stop_task:
            return {"success": True, "message": "Stop task already exists", "status": "STOPPING"}
        
        # Create stop task
        create_task(
            db,
            host_id=run.host_id,
            task_type="stop_simulation",
            parameters={"run_id": run_id},
            run_id=run_id
        )
        
        # Mark run as STOPPING
        run.status = RunStatus.STOPPING
        
        # Create event
        create_run_event(db, run_id, EventType.STOP_REQUESTED, run.host_id, {
            "reason": "Stopped by user",
            "previous_status": "RUNNING"
        })
        
        db.commit()
        return {
            "success": True,
            "message": "Stop task created, waiting for agent",
            "status": "STOPPING"
        }
    
    return {"success": False, "message": f"Unexpected run status: {run.status.value}"}


def delete_run(db: Session, run_id: int, force: bool = False) -> dict:
    """
    Delete a run and all related data.
    Returns dict with deletion counts.
    """
    run = get_run_by_id(db, run_id)
    if not run:
        return {"success": False, "message": "Run not found"}
    
    # Safety check: block deletion of RUNNING/STOPPING runs unless force=True
    if run.status in [RunStatus.RUNNING, RunStatus.STOPPING] and not force:
        return {
            "success": False,
            "message": f"Cannot delete {run.status.value} run without force=true"
        }
    
    # If force=True and run is RUNNING/STOPPING, try to stop it first
    if force and run.status in [RunStatus.RUNNING, RunStatus.STOPPING]:
        stop_result = stop_run(db, run_id)
        # Wait a moment for stop to process
        db.refresh(run)
    
    # Count related objects before deletion
    counts = {
        "tasks": db.query(Task).filter(Task.run_id == run_id).count(),
        "alerts": db.query(Alert).filter(Alert.run_id == run_id).count(),
        "events": db.query(RunEvent).filter(RunEvent.run_id == run_id).count(),
        "metrics": db.query(Metric).filter(Metric.run_id == run_id).count(),
        "iocs": db.query(IOC).filter(IOC.run_id == run_id).count(),
        "affected_files": db.query(AffectedFile).filter(AffectedFile.run_id == run_id).count()
    }
    
    # Delete related objects (cascade)
    # Tasks
    db.query(Task).filter(Task.run_id == run_id).delete()
    
    # Alerts
    db.query(Alert).filter(Alert.run_id == run_id).delete()
    
    # Events
    db.query(RunEvent).filter(RunEvent.run_id == run_id).delete()
    
    # Metrics
    db.query(Metric).filter(Metric.run_id == run_id).delete()
    
    # IOCs
    db.query(IOC).filter(IOC.run_id == run_id).delete()
    
    # Affected Files
    db.query(AffectedFile).filter(AffectedFile.run_id == run_id).delete()
    
    # Advanced features (if they exist)
    # Recovery Plans
    from .models import RecoveryPlan, RecoveryEvent, BehaviorProfile, WhatIfScenario
    from .models import IRSession, RunFeedback, BusinessImpact, ComplianceReport
    
    # Recovery events (via recovery plans)
    recovery_plans = db.query(RecoveryPlan).filter(RecoveryPlan.run_id == run_id).all()
    for plan in recovery_plans:
        db.query(RecoveryEvent).filter(RecoveryEvent.recovery_plan_id == plan.id).delete()
        counts["recovery_events"] = counts.get("recovery_events", 0) + 1
    
    # Recovery Plans
    recovery_count = db.query(RecoveryPlan).filter(RecoveryPlan.run_id == run_id).count()
    db.query(RecoveryPlan).filter(RecoveryPlan.run_id == run_id).delete()
    counts["recovery_plans"] = recovery_count
    
    # Behavior Profiles
    behavior_count = db.query(BehaviorProfile).filter(BehaviorProfile.run_id == run_id).count()
    db.query(BehaviorProfile).filter(BehaviorProfile.run_id == run_id).delete()
    counts["behavior_profiles"] = behavior_count
    
    # What-If Scenarios
    whatif_count = db.query(WhatIfScenario).filter(WhatIfScenario.run_id == run_id).count()
    db.query(WhatIfScenario).filter(WhatIfScenario.run_id == run_id).delete()
    counts["whatif_scenarios"] = whatif_count
    
    # IR Sessions
    ir_count = db.query(IRSession).filter(IRSession.run_id == run_id).count()
    db.query(IRSession).filter(IRSession.run_id == run_id).delete()
    counts["ir_sessions"] = ir_count
    
    # Run Feedback
    feedback_count = db.query(RunFeedback).filter(RunFeedback.run_id == run_id).count()
    db.query(RunFeedback).filter(RunFeedback.run_id == run_id).delete()
    counts["run_feedbacks"] = feedback_count
    
    # Business Impact
    impact_count = db.query(BusinessImpact).filter(BusinessImpact.run_id == run_id).count()
    db.query(BusinessImpact).filter(BusinessImpact.run_id == run_id).delete()
    counts["business_impacts"] = impact_count
    
    # Compliance Reports
    compliance_count = db.query(ComplianceReport).filter(ComplianceReport.run_id == run_id).count()
    db.query(ComplianceReport).filter(ComplianceReport.run_id == run_id).delete()
    counts["compliance_reports"] = compliance_count
    
    # Finally, delete the run itself
    db.delete(run)
    db.commit()
    
    return {
        "success": True,
        "deleted": True,
        "run_id": run_id,
        "counts": counts
    }


# ============ Task Operations ============

def get_task_by_id(db: Session, task_id: int) -> Optional[Task]:
    return db.query(Task).filter(Task.id == task_id).first()


def get_pending_task_for_host(db: Session, host_id: int) -> Optional[Task]:
    """Get the oldest pending task for a host."""
    return db.query(Task).filter(
        Task.host_id == host_id,
        Task.status == TaskStatus.PENDING
    ).order_by(Task.created_at).first()


def get_tasks_by_run(db: Session, run_id: int) -> List[Task]:
    return db.query(Task).filter(Task.run_id == run_id).order_by(Task.created_at).all()


def create_task(
    db: Session,
    host_id: int,
    task_type: str,
    parameters: dict,
    run_id: Optional[int] = None
) -> Task:
    task = Task(
        host_id=host_id,
        run_id=run_id,
        type=task_type,
        parameters=parameters,
        status=TaskStatus.PENDING
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def mark_task_sent(db: Session, task_id: int):
    task = get_task_by_id(db, task_id)
    if task:
        task.status = TaskStatus.SENT
        # Also mark the run as RUNNING if it's still PENDING
        if task.run_id:
            run = get_run_by_id(db, task.run_id)
            if run and run.status == RunStatus.PENDING:
                run.status = RunStatus.RUNNING
                run.started_at = datetime.utcnow()
        db.commit()


def complete_task(db: Session, task_id: int, status: str, result_message: Optional[str] = None):
    task = get_task_by_id(db, task_id)
    if task:
        task.status = TaskStatus.COMPLETED if status == "completed" else TaskStatus.FAILED
        task.completed_at = datetime.utcnow()
        task.result_message = result_message
        
        # Handle stop_simulation task completion
        if task.type == "stop_simulation" and task.run_id and status == "completed":
            run = get_run_by_id(db, task.run_id)
            if run and run.status == RunStatus.STOPPING:
                run.status = RunStatus.CANCELED
                run.ended_at = datetime.utcnow()
                
                # Create STOP_EXECUTED event
                create_run_event(db, task.run_id, EventType.STOP_EXECUTED, run.host_id, {
                    "task_id": task_id,
                    "result": result_message
                })
        
        db.commit()
        
        # Check if all tasks for the run are done
        if task.run_id:
            check_run_completion(db, task.run_id)


def check_run_completion(db: Session, run_id: int):
    """Check if all tasks for a run are completed and update run status."""
    run = get_run_by_id(db, run_id)
    if not run or run.status not in [RunStatus.PENDING, RunStatus.RUNNING]:
        return
    
    tasks = get_tasks_by_run(db, run_id)
    if not tasks:
        return
    
    all_done = all(t.status in [TaskStatus.COMPLETED, TaskStatus.FAILED] for t in tasks)
    if all_done:
        any_failed = any(t.status == TaskStatus.FAILED for t in tasks)
        run.status = RunStatus.FAILED if any_failed else RunStatus.COMPLETED
        run.ended_at = datetime.utcnow()
        db.commit()


# ============ Alert Operations ============

def get_alert_by_id(db: Session, alert_id: int) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.id == alert_id).first()


def get_all_alerts(db: Session, limit: int = 100) -> List[Alert]:
    return db.query(Alert).order_by(desc(Alert.timestamp)).limit(limit).all()


def get_alerts(
    db: Session,
    limit: int = 50,
    since: datetime = None,
    min_severity: int = 0
) -> List[Alert]:
    """Get alerts with optional filters for SSE/REST endpoints."""
    query = db.query(Alert)
    
    if since:
        query = query.filter(Alert.timestamp >= since)
    
    if min_severity > 0:
        query = query.filter(Alert.severity >= min_severity)
    
    return query.order_by(desc(Alert.timestamp)).limit(limit).all()


def get_alerts_by_run(db: Session, run_id: int) -> List[Alert]:
    return db.query(Alert).filter(Alert.run_id == run_id).order_by(Alert.timestamp).all()


def get_alerts_by_host(db: Session, host_id: int) -> List[Alert]:
    return db.query(Alert).filter(Alert.host_id == host_id).order_by(desc(Alert.timestamp)).all()


def create_alert(
    db: Session,
    rule_id: str,
    rule_description: Optional[str],
    agent_name: Optional[str],
    severity: int,
    timestamp: datetime,
    raw: dict,
    host_id: Optional[int] = None,
    run_id: Optional[int] = None
) -> Alert:
    alert = Alert(
        host_id=host_id,
        run_id=run_id,
        rule_id=rule_id,
        rule_description=rule_description,
        agent_name=agent_name,
        severity=severity,
        timestamp=timestamp,
        raw=raw
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def count_alerts(db: Session) -> int:
    return db.query(Alert).count()


# ============ Playbook Operations ============

def get_playbook_by_rule_id(db: Session, rule_id: str) -> Optional[Playbook]:
    return db.query(Playbook).filter(
        Playbook.rule_id == rule_id,
        Playbook.enabled == True
    ).first()


def get_all_playbooks(db: Session) -> List[Playbook]:
    return db.query(Playbook).all()


def create_playbook(db: Session, name: str, rule_id: str, actions: list, enabled: bool = True) -> Playbook:
    playbook = Playbook(
        name=name,
        rule_id=rule_id,
        actions=actions,
        enabled=enabled
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return playbook


# ============ RunEvent Operations ============

def create_run_event(
    db: Session,
    run_id: int,
    event_type: EventType,
    host_id: Optional[int] = None,
    details: Optional[dict] = None
) -> RunEvent:
    event = RunEvent(
        run_id=run_id,
        host_id=host_id,
        event_type=event_type,
        details=details
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def get_events_by_run(db: Session, run_id: int) -> List[RunEvent]:
    return db.query(RunEvent).filter(
        RunEvent.run_id == run_id
    ).order_by(RunEvent.timestamp).all()


# ============ AffectedFile Operations ============

def create_affected_file(
    db: Session,
    run_id: int,
    original_path: str,
    action_type: FileActionType,
    host_id: Optional[int] = None,
    new_path: Optional[str] = None
) -> AffectedFile:
    af = AffectedFile(
        run_id=run_id,
        host_id=host_id,
        original_path=original_path,
        new_path=new_path,
        action_type=action_type
    )
    db.add(af)
    db.commit()
    db.refresh(af)
    return af


def bulk_create_affected_files(db: Session, files: List[dict]) -> int:
    """Bulk create affected files. Returns count created."""
    count = 0
    for f in files:
        af = AffectedFile(
            run_id=f.get('run_id'),
            host_id=f.get('host_id'),
            original_path=f.get('original_path'),
            new_path=f.get('new_path'),
            action_type=FileActionType(f.get('action_type', 'RENAMED'))
        )
        db.add(af)
        count += 1
    db.commit()
    return count


def get_affected_files_by_run(db: Session, run_id: int) -> List[AffectedFile]:
    return db.query(AffectedFile).filter(
        AffectedFile.run_id == run_id
    ).order_by(AffectedFile.timestamp).all()


def count_affected_files_by_run(db: Session, run_id: int) -> int:
    return db.query(AffectedFile).filter(AffectedFile.run_id == run_id).count()


# ============ Metric Operations ============

def create_metric(
    db: Session,
    run_id: int,
    name: str,
    value: float,
    host_id: Optional[int] = None
) -> Metric:
    metric = Metric(
        run_id=run_id,
        host_id=host_id,
        name=name,
        value=value
    )
    db.add(metric)
    db.commit()
    db.refresh(metric)
    return metric


def get_metrics_by_run(db: Session, run_id: int) -> List[Metric]:
    return db.query(Metric).filter(Metric.run_id == run_id).all()


# ============ IOC Operations ============

def create_ioc(
    db: Session,
    run_id: int,
    ioc_type: IOCType,
    value: str,
    context: Optional[str] = None,
    host_id: Optional[int] = None
) -> IOC:
    ioc = IOC(
        run_id=run_id,
        host_id=host_id,
        ioc_type=ioc_type,
        value=value,
        context=context
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


def bulk_create_iocs(db: Session, iocs: List[dict]) -> int:
    """Bulk create IOCs. Returns count created."""
    count = 0
    for i in iocs:
        ioc = IOC(
            run_id=i.get('run_id'),
            host_id=i.get('host_id'),
            ioc_type=IOCType(i.get('ioc_type', 'FILE_PATH')),
            value=i.get('value'),
            context=i.get('context')
        )
        db.add(ioc)
        count += 1
    db.commit()
    return count


def get_iocs_by_run(db: Session, run_id: int) -> List[IOC]:
    return db.query(IOC).filter(IOC.run_id == run_id).all()


# ============ ELKConfig Operations ============

def get_elk_config(db: Session) -> Optional[ELKConfig]:
    return db.query(ELKConfig).filter(ELKConfig.enabled == True).first()


def create_or_update_elk_config(
    db: Session,
    url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    index_alerts: str = '.alerts-security.alerts-*',
    index_logs: str = 'logs-*',
    enabled: bool = True
) -> ELKConfig:
    config = db.query(ELKConfig).first()
    if config:
        config.url = url
        config.username = username
        if password:
            config.password = password
        if api_key:
            config.api_key = api_key
        config.index_alerts = index_alerts
        config.index_logs = index_logs
        config.enabled = enabled
        config.updated_at = datetime.utcnow()
    else:
        config = ELKConfig(
            url=url,
            username=username,
            password=password,
            api_key=api_key,
            index_alerts=index_alerts,
            index_logs=index_logs,
            enabled=enabled
        )
        db.add(config)
    db.commit()
    db.refresh(config)
    return config


def update_elk_last_sync(db: Session):
    config = get_elk_config(db)
    if config:
        config.last_sync = datetime.utcnow()
        db.commit()


# ============ Alert Extended Operations ============

def get_alerts_filtered(
    db: Session,
    host_id: Optional[int] = None,
    rule_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    min_severity: Optional[int] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Alert]:
    query = db.query(Alert)
    
    if host_id:
        query = query.filter(Alert.host_id == host_id)
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)
    if start_time:
        query = query.filter(Alert.timestamp >= start_time)
    if end_time:
        query = query.filter(Alert.timestamp <= end_time)
    if min_severity:
        query = query.filter(Alert.severity >= min_severity)
    
    return query.order_by(desc(Alert.timestamp)).offset(offset).limit(limit).all()


def get_alert_stats(db: Session, hours: int = 24) -> dict:
    """Get alert statistics for the last N hours."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Total alerts
    total = db.query(Alert).filter(Alert.timestamp >= since).count()
    
    # Alerts by rule
    by_rule = db.query(
        Alert.rule_id, func.count(Alert.id)
    ).filter(Alert.timestamp >= since).group_by(Alert.rule_id).all()
    
    # Alerts by severity bucket
    by_severity = {
        'critical': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity >= 12).count(),
        'high': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity >= 8, Alert.severity < 12).count(),
        'medium': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity >= 4, Alert.severity < 8).count(),
        'low': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity < 4).count()
    }
    
    return {
        'total_alerts': total,
        'alerts_by_rule': {r[0]: r[1] for r in by_rule},
        'alerts_by_severity': by_severity
    }


def get_alerts_over_time(db: Session, hours: int = 24, bucket_hours: int = 1) -> List[dict]:
    """Get alert counts bucketed by time."""
    results = []
    now = datetime.utcnow()
    
    for i in range(hours // bucket_hours):
        end = now - timedelta(hours=i * bucket_hours)
        start = end - timedelta(hours=bucket_hours)
        count = db.query(Alert).filter(
            Alert.timestamp >= start,
            Alert.timestamp < end
        ).count()
        results.append({
            'time': start.isoformat(),
            'count': count
        })
    
    return list(reversed(results))


# ============ Host Isolation Operations ============

def update_host_isolation(
    db: Session,
    host_id: int,
    is_isolated: bool,
    isolation_policy: Optional[str] = None
) -> Optional[Host]:
    """Update host isolation status."""
    host = get_host_by_id(db, host_id)
    if host:
        host.is_isolated = is_isolated
        if is_isolated:
            host.last_isolated_at = datetime.utcnow()
            if isolation_policy:
                host.isolation_policy = isolation_policy
        else:
            host.last_deisolated_at = datetime.utcnow()
        db.commit()
        db.refresh(host)
    return host


def set_host_isolation_policy(
    db: Session,
    host_id: int,
    policy: str
) -> Optional[Host]:
    """Set the isolation policy for a host."""
    host = get_host_by_id(db, host_id)
    if host:
        host.isolation_policy = policy
        db.commit()
        db.refresh(host)
    return host


# ============ Recovery Plan Operations ============

def get_recovery_plan_by_id(db: Session, plan_id: int) -> Optional[RecoveryPlan]:
    return db.query(RecoveryPlan).filter(RecoveryPlan.id == plan_id).first()


def get_recovery_plan_by_run(db: Session, run_id: int) -> Optional[RecoveryPlan]:
    return db.query(RecoveryPlan).filter(RecoveryPlan.run_id == run_id).first()


def get_recovery_plans_by_host(db: Session, host_id: int) -> List[RecoveryPlan]:
    return db.query(RecoveryPlan).filter(
        RecoveryPlan.host_id == host_id
    ).order_by(desc(RecoveryPlan.created_at)).all()


def create_recovery_plan(
    db: Session,
    run_id: int,
    host_id: int,
    notes: Optional[str] = None
) -> RecoveryPlan:
    plan = RecoveryPlan(
        run_id=run_id,
        host_id=host_id,
        status=RecoveryPlanStatus.PLANNED,
        notes=notes
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


def update_recovery_plan_status(
    db: Session,
    plan_id: int,
    status: RecoveryPlanStatus,
    completed_at: Optional[datetime] = None
) -> Optional[RecoveryPlan]:
    plan = get_recovery_plan_by_id(db, plan_id)
    if plan:
        plan.status = status
        if completed_at:
            plan.completed_at = completed_at
        elif status in [RecoveryPlanStatus.COMPLETED, RecoveryPlanStatus.FAILED]:
            plan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(plan)
    return plan


# ============ Recovery Event Operations ============

def create_recovery_event(
    db: Session,
    recovery_plan_id: int,
    event_type: RecoveryEventType,
    details: Optional[dict] = None
) -> RecoveryEvent:
    event = RecoveryEvent(
        recovery_plan_id=recovery_plan_id,
        event_type=event_type,
        details=details
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def get_recovery_events_by_plan(db: Session, plan_id: int) -> List[RecoveryEvent]:
    return db.query(RecoveryEvent).filter(
        RecoveryEvent.recovery_plan_id == plan_id
    ).order_by(RecoveryEvent.timestamp).all()


# ============ Recovery Task Tracking ============

def get_recovery_tasks_by_run(db: Session, run_id: int) -> List[Task]:
    """Get all recovery-related tasks for a run."""
    return db.query(Task).filter(
        Task.run_id == run_id,
        Task.type.in_([
            "response_deisolate_host",
            "recovery_enable_user",
            "recovery_restore_files_from_quarantine"
        ])
    ).order_by(Task.created_at).all()


def get_containment_tasks_by_run(db: Session, run_id: int) -> List[Task]:
    """Get all containment-related tasks for a run."""
    return db.query(Task).filter(
        Task.run_id == run_id,
        Task.type.in_([
            "response_isolate_host",
            "response_reisolate_host",
            "response_kill_process",
            "response_disable_user"
        ])
    ).order_by(Task.created_at).all()


def check_recovery_plan_completion(db: Session, plan_id: int) -> bool:
    """
    Check if all recovery tasks for a plan are completed.
    Returns True if plan status was updated to COMPLETED or FAILED.
    """
    plan = get_recovery_plan_by_id(db, plan_id)
    if not plan or plan.status in [RecoveryPlanStatus.COMPLETED, RecoveryPlanStatus.FAILED]:
        return False
    
    recovery_tasks = get_recovery_tasks_by_run(db, plan.run_id)
    if not recovery_tasks:
        return False
    
    all_done = all(t.status in [TaskStatus.COMPLETED, TaskStatus.FAILED] for t in recovery_tasks)
    if all_done:
        any_failed = any(t.status == TaskStatus.FAILED for t in recovery_tasks)
        new_status = RecoveryPlanStatus.FAILED if any_failed else RecoveryPlanStatus.COMPLETED
        update_recovery_plan_status(db, plan_id, new_status)
        return True
    return False


# ============ Business Impact Recovery Update ============

def update_business_impact_actuals(
    db: Session,
    run_id: int,
    actual_recovery_hours: float,
    cost_per_hour: Optional[float] = None
) -> Optional[BusinessImpact]:
    """Update business impact with actual recovery metrics."""
    impact = db.query(BusinessImpact).filter(BusinessImpact.run_id == run_id).first()
    if impact:
        impact.actual_recovery_hours = actual_recovery_hours
        if cost_per_hour:
            impact.actual_total_cost = actual_recovery_hours * cost_per_hour
        else:
            impact.actual_total_cost = actual_recovery_hours * impact.assumed_cost_per_hour
        db.commit()
        db.refresh(impact)
    return impact


# ============ Compliance Report Recovery Update ============

def update_compliance_report_recovery(
    db: Session,
    run_id: int,
    deisolation_time: Optional[datetime] = None,
    recovery_completed_time: Optional[datetime] = None,
    containment_summary: Optional[str] = None,
    recovery_summary: Optional[str] = None
) -> Optional[ComplianceReport]:
    """Update compliance report with recovery information."""
    report = db.query(ComplianceReport).filter(ComplianceReport.run_id == run_id).first()
    if report:
        if deisolation_time:
            report.incident_deisolation = deisolation_time
        if recovery_completed_time:
            report.incident_recovery_completed = recovery_completed_time
        if containment_summary:
            report.containment_actions_summary = containment_summary
        if recovery_summary:
            report.recovery_actions_summary = recovery_summary
        db.commit()
        db.refresh(report)
    return report
