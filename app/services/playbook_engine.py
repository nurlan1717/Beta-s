"""
Playbook Engine - Orchestrates automated response playbooks.

Handles:
- Playbook triggering based on alerts
- Action execution with idempotency
- Approval workflows
- Dry-run mode
- Safety controls
"""

import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session

from ..models import Alert, Host, Playbook, PlaybookAction, ResponseExecution, Task, ResponseExecutionStatus
from .isolation_engine import IsolationEngine

logger = logging.getLogger(__name__)


class PlaybookEngine:
    """Orchestrates automated response playbooks."""
    
    def __init__(self, db: Session):
        self.db = db
        self.isolation_engine = IsolationEngine(db)
    
    def find_matching_playbooks(self, alert: Alert) -> List[Playbook]:
        """
        Find all enabled playbooks that match the alert.
        
        Args:
            alert: Alert to match against
            
        Returns:
            List of matching playbooks
        """
        playbooks = self.db.query(Playbook).filter(
            Playbook.enabled == True,
            Playbook.trigger_rule_id == alert.rule_id,
            Playbook.severity_threshold <= alert.severity
        ).all()
        
        logger.info(f"Found {len(playbooks)} matching playbooks for alert {alert.id} (rule: {alert.rule_id})")
        return playbooks
    
    def should_execute_playbook(
        self, 
        playbook: Playbook, 
        alert: Alert, 
        host: Host,
        force: bool = False
    ) -> tuple[bool, str]:
        """
        Check if playbook should execute based on safety controls.
        
        Args:
            playbook: Playbook to check
            alert: Triggering alert
            host: Target host
            force: Force execution even if already executed
            
        Returns:
            (should_execute, reason)
        """
        # Check if already executed (idempotency)
        if not force:
            execution_hash = self._generate_execution_hash(alert.id, playbook.id)
            existing = self.db.query(ResponseExecution).filter(
                ResponseExecution.execution_hash == execution_hash,
                ResponseExecution.status.in_([
                    ResponseExecutionStatus.COMPLETED,
                    ResponseExecutionStatus.RUNNING,
                    ResponseExecutionStatus.APPROVED
                ])
            ).first()
            
            if existing:
                return False, f"Playbook already executed (execution_id: {existing.id})"
        
        # Check host allows auto-response
        if not host.allow_auto_response and not playbook.requires_approval:
            return False, "Host does not allow auto-response"
        
        # Check global auto-response setting
        auto_response_enabled = self._get_system_config("auto_response_enabled", "true")
        if auto_response_enabled.lower() != "true" and not playbook.requires_approval:
            return False, "Global auto-response is disabled"
        
        return True, "OK"
    
    def execute_playbook(
        self,
        playbook: Playbook,
        alert: Alert,
        host: Host,
        dry_run: bool = False,
        force: bool = False,
        initiated_by: str = "system"
    ) -> Dict[str, Any]:
        """
        Execute a playbook for an alert.
        
        Args:
            playbook: Playbook to execute
            alert: Triggering alert
            host: Target host
            dry_run: If True, simulate execution without making changes
            force: Force execution even if already executed
            initiated_by: User or system that initiated execution
            
        Returns:
            Execution results dictionary
        """
        logger.info(f"Executing playbook {playbook.code} for alert {alert.id} on host {host.name} (dry_run={dry_run})")
        
        # Check if should execute
        should_execute, reason = self.should_execute_playbook(playbook, alert, host, force)
        if not should_execute:
            logger.warning(f"Playbook execution blocked: {reason}")
            return {
                "success": False,
                "message": reason,
                "actions_executed": 0
            }
        
        # Update playbook stats
        playbook.last_triggered_at = datetime.utcnow()
        playbook.trigger_count += 1
        self.db.commit()
        
        # Execute actions in order
        results = []
        actions_executed = 0
        actions_failed = 0
        
        for action in playbook.actions:
            # Check if requires approval
            if action.requires_approval or playbook.requires_approval:
                execution = self._create_execution_record(
                    playbook, action, alert, host, dry_run, initiated_by
                )
                execution.status = ResponseExecutionStatus.REQUIRES_APPROVAL
                execution.result_message = "Waiting for manual approval"
                self.db.commit()
                
                results.append({
                    "action": action.action_type,
                    "status": "requires_approval",
                    "execution_id": execution.id
                })
                continue
            
            # Execute action
            try:
                result = self._execute_action(
                    action, alert, host, dry_run, playbook, initiated_by
                )
                results.append(result)
                
                if result["success"]:
                    actions_executed += 1
                else:
                    actions_failed += 1
                    if not action.continue_on_failure:
                        logger.warning(f"Action {action.action_type} failed, stopping playbook execution")
                        break
                        
            except Exception as e:
                logger.error(f"Error executing action {action.action_type}: {e}", exc_info=True)
                actions_failed += 1
                results.append({
                    "action": action.action_type,
                    "success": False,
                    "error": str(e)
                })
                if not action.continue_on_failure:
                    break
        
        return {
            "success": actions_failed == 0,
            "playbook_code": playbook.code,
            "playbook_name": playbook.name,
            "actions_executed": actions_executed,
            "actions_failed": actions_failed,
            "dry_run": dry_run,
            "results": results
        }
    
    def _execute_action(
        self,
        action: PlaybookAction,
        alert: Alert,
        host: Host,
        dry_run: bool,
        playbook: Playbook,
        initiated_by: str
    ) -> Dict[str, Any]:
        """Execute a single playbook action."""
        
        # Create execution record
        execution = self._create_execution_record(
            playbook, action, alert, host, dry_run, initiated_by
        )
        execution.status = ResponseExecutionStatus.RUNNING
        execution.started_at = datetime.utcnow()
        self.db.commit()
        
        try:
            # Route to appropriate handler
            action_type = action.action_type.lower()
            params = action.parameters or {}
            
            if action_type == "kill_process":
                result = self._action_kill_process(host, params, dry_run)
            elif action_type == "isolate_host":
                result = self._action_isolate_host(host, params, dry_run, alert.id, playbook.id)
            elif action_type == "disable_user":
                result = self._action_disable_user(host, params, dry_run)
            elif action_type == "collect_triage":
                result = self._action_collect_triage(host, params, dry_run)
            elif action_type == "block_ip":
                result = self._action_block_ip(host, params, dry_run)
            elif action_type == "create_incident":
                result = self._action_create_incident(host, alert, params, dry_run)
            elif action_type == "escalate_alert":
                result = self._action_escalate_alert(alert, params, dry_run)
            else:
                result = {
                    "success": False,
                    "message": f"Unknown action type: {action_type}"
                }
            
            # Update execution record
            execution.status = ResponseExecutionStatus.COMPLETED if result["success"] else ResponseExecutionStatus.FAILED
            execution.completed_at = datetime.utcnow()
            execution.result_message = result.get("message", "")
            execution.result_data = result.get("data", {})
            if not result["success"]:
                execution.error_message = result.get("error", "Action failed")
            
            self.db.commit()
            
            return {
                "action": action.action_type,
                "success": result["success"],
                "message": result.get("message", ""),
                "execution_id": execution.id,
                "dry_run": dry_run
            }
            
        except Exception as e:
            execution.status = ResponseExecutionStatus.FAILED
            execution.completed_at = datetime.utcnow()
            execution.error_message = str(e)
            self.db.commit()
            raise
    
    # Action Handlers
    
    def _action_kill_process(self, host: Host, params: Dict, dry_run: bool) -> Dict:
        """Kill a process on the host."""
        process_name = params.get("process_name", "")
        
        task = Task(
            host_id=host.id,
            type="response_kill_process",
            parameters={"process_name": process_name, "dry_run": dry_run},
            status="PENDING"
        )
        self.db.add(task)
        self.db.commit()
        
        return {
            "success": True,
            "message": f"{'[DRY RUN] ' if dry_run else ''}Kill process task created: {process_name}",
            "data": {"task_id": task.id, "process_name": process_name}
        }
    
    def _action_isolate_host(self, host: Host, params: Dict, dry_run: bool, alert_id: int, playbook_id: int) -> Dict:
        """Isolate the host using isolation engine."""
        policy = params.get("policy", "HYBRID")
        ttl_minutes = params.get("ttl_minutes")
        
        result = self.isolation_engine.isolate_host(
            host=host,
            policy=policy,
            ttl_minutes=ttl_minutes,
            dry_run=dry_run,
            triggered_by="playbook",
            alert_id=alert_id,
            playbook_id=playbook_id
        )
        
        return result
    
    def _action_disable_user(self, host: Host, params: Dict, dry_run: bool) -> Dict:
        """Disable a user account."""
        username = params.get("username", "")
        
        task = Task(
            host_id=host.id,
            type="response_disable_user",
            parameters={"username": username, "dry_run": dry_run},
            status="PENDING"
        )
        self.db.add(task)
        self.db.commit()
        
        return {
            "success": True,
            "message": f"{'[DRY RUN] ' if dry_run else ''}Disable user task created: {username}",
            "data": {"task_id": task.id, "username": username}
        }
    
    def _action_collect_triage(self, host: Host, params: Dict, dry_run: bool) -> Dict:
        """Collect triage data from host."""
        triage_type = params.get("triage_type", "standard")
        
        task = Task(
            host_id=host.id,
            type="collect_triage",
            parameters={"triage_type": triage_type, "dry_run": dry_run},
            status="PENDING"
        )
        self.db.add(task)
        self.db.commit()
        
        return {
            "success": True,
            "message": f"{'[DRY RUN] ' if dry_run else ''}Triage collection task created",
            "data": {"task_id": task.id, "triage_type": triage_type}
        }
    
    def _action_block_ip(self, host: Host, params: Dict, dry_run: bool) -> Dict:
        """Block an IP address."""
        ip_address = params.get("ip_address", "")
        direction = params.get("direction", "both")  # inbound, outbound, both
        
        task = Task(
            host_id=host.id,
            type="block_ip",
            parameters={"ip_address": ip_address, "direction": direction, "dry_run": dry_run},
            status="PENDING"
        )
        self.db.add(task)
        self.db.commit()
        
        return {
            "success": True,
            "message": f"{'[DRY RUN] ' if dry_run else ''}Block IP task created: {ip_address}",
            "data": {"task_id": task.id, "ip_address": ip_address}
        }
    
    def _action_create_incident(self, host: Host, alert: Alert, params: Dict, dry_run: bool) -> Dict:
        """Create an incident record."""
        if dry_run:
            return {
                "success": True,
                "message": "[DRY RUN] Would create incident record",
                "data": {"alert_id": alert.id, "host_id": host.id}
            }
        
        # In a real implementation, this would create an incident in an ITSM system
        # For now, we'll just log it
        logger.info(f"Incident created for alert {alert.id} on host {host.name}")
        
        return {
            "success": True,
            "message": "Incident record created",
            "data": {"alert_id": alert.id, "host_id": host.id}
        }
    
    def _action_escalate_alert(self, alert: Alert, params: Dict, dry_run: bool) -> Dict:
        """Escalate alert severity or notification."""
        if dry_run:
            return {
                "success": True,
                "message": "[DRY RUN] Would escalate alert",
                "data": {"alert_id": alert.id}
            }
        
        # Increase severity
        new_severity = min(alert.severity + params.get("severity_increase", 1), 10)
        alert.severity = new_severity
        self.db.commit()
        
        return {
            "success": True,
            "message": f"Alert escalated to severity {new_severity}",
            "data": {"alert_id": alert.id, "new_severity": new_severity}
        }
    
    # Helper methods
    
    def _create_execution_record(
        self,
        playbook: Playbook,
        action: PlaybookAction,
        alert: Alert,
        host: Host,
        dry_run: bool,
        initiated_by: str
    ) -> ResponseExecution:
        """Create a response execution record."""
        execution_hash = self._generate_execution_hash(alert.id, playbook.id, action.action_type)
        
        execution = ResponseExecution(
            alert_id=alert.id,
            playbook_id=playbook.id,
            playbook_action_id=action.id,
            host_id=host.id,
            action_type=action.action_type,
            parameters=action.parameters,
            status=ResponseExecutionStatus.PENDING,
            dry_run=dry_run,
            requires_approval=action.requires_approval or playbook.requires_approval,
            execution_hash=execution_hash,
            created_by=initiated_by
        )
        
        self.db.add(execution)
        self.db.commit()
        return execution
    
    def _generate_execution_hash(self, alert_id: int, playbook_id: int, action_type: str = "") -> str:
        """Generate hash for idempotency checking."""
        data = f"{alert_id}:{playbook_id}:{action_type}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _get_system_config(self, key: str, default: str = "") -> str:
        """Get system configuration value."""
        from ..models import SystemConfig
        config = self.db.query(SystemConfig).filter(SystemConfig.key == key).first()
        return config.value if config else default
