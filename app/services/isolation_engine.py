"""
Isolation Engine - Manages host isolation with advanced policies.

Handles:
- Multiple isolation policies (FIREWALL_BLOCK, OUTBOUND_ONLY, RANSOMRUN_CONTROLLED, etc.)
- TTL-based auto-unisolation
- Escape hatch for emergency de-isolation
- Audit trail of all isolation events
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from sqlalchemy.orm import Session

from ..models import Host, Task, IsolationPolicy

logger = logging.getLogger(__name__)


class IsolationEngine:
    """Manages host isolation with advanced policies and safety controls."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def isolate_host(
        self,
        host: Host,
        policy: str = "HYBRID",
        ttl_minutes: Optional[int] = None,
        dry_run: bool = False,
        triggered_by: str = "manual",
        initiated_by_user: Optional[str] = None,
        alert_id: Optional[int] = None,
        playbook_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Isolate a host using specified policy.
        
        Args:
            host: Host to isolate
            policy: Isolation policy to apply
            ttl_minutes: Auto-unisolate after X minutes (optional)
            dry_run: If True, simulate without making changes
            triggered_by: What triggered isolation (playbook, manual, etc.)
            initiated_by_user: User who initiated (if manual)
            alert_id: Associated alert ID
            playbook_id: Associated playbook ID
            
        Returns:
            Result dictionary with success status and details
        """
        logger.info(f"Isolating host {host.name} with policy {policy} (dry_run={dry_run}, ttl={ttl_minutes})")
        
        # Validate policy
        try:
            isolation_policy = IsolationPolicy[policy]
        except KeyError:
            return {
                "success": False,
                "message": f"Invalid isolation policy: {policy}",
                "error": f"Valid policies: {[p.value for p in IsolationPolicy]}"
            }
        
        # Calculate expiration if TTL provided
        expires_at = None
        if ttl_minutes:
            expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
        
        # Create isolation event record
        event = IsolationEvent(
            host_id=host.id,
            event_type="ISOLATE",
            isolation_policy=policy,
            ttl_minutes=ttl_minutes,
            expires_at=expires_at,
            triggered_by=triggered_by,
            alert_id=alert_id,
            playbook_id=playbook_id,
            initiated_by_user=initiated_by_user,
            dry_run=dry_run,
            timestamp=datetime.utcnow()
        )
        
        if dry_run:
            event.success = True
            event.error_message = None
            self.db.add(event)
            self.db.commit()
            
            return {
                "success": True,
                "message": f"[DRY RUN] Would isolate host {host.name} with policy {policy}",
                "data": {
                    "host_id": host.id,
                    "policy": policy,
                    "ttl_minutes": ttl_minutes,
                    "event_id": event.id
                }
            }
        
        # Create isolation task for agent
        task_params = {
            "policy": policy,
            "ttl_minutes": ttl_minutes,
            "server_ip": self._get_server_ip(),
            "escape_hatch_enabled": True
        }
        
        task = Task(
            host_id=host.id,
            type="isolate_host",
            parameters=task_params,
            status="PENDING"
        )
        self.db.add(task)
        
        # Update host isolation status
        host.is_isolated = True
        host.isolation_policy = isolation_policy
        host.isolation_ttl_minutes = ttl_minutes
        host.isolation_expires_at = expires_at
        host.last_isolated_at = datetime.utcnow()
        host.quarantine_status = "QUARANTINED"
        
        # Record firewall rules that will be applied (for escape hatch)
        firewall_rules = self._get_firewall_rules_for_policy(policy, host)
        event.firewall_rules_applied = firewall_rules
        event.success = True
        
        self.db.add(event)
        self.db.commit()
        
        logger.info(f"Host {host.name} isolated successfully with policy {policy}")
        
        return {
            "success": True,
            "message": f"Host {host.name} isolated with policy {policy}",
            "data": {
                "host_id": host.id,
                "policy": policy,
                "ttl_minutes": ttl_minutes,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "task_id": task.id,
                "event_id": event.id
            }
        }
    
    def deisolate_host(
        self,
        host: Host,
        dry_run: bool = False,
        triggered_by: str = "manual",
        initiated_by_user: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Remove isolation from a host (escape hatch).
        
        Args:
            host: Host to de-isolate
            dry_run: If True, simulate without making changes
            triggered_by: What triggered de-isolation
            initiated_by_user: User who initiated
            
        Returns:
            Result dictionary
        """
        logger.info(f"De-isolating host {host.name} (dry_run={dry_run})")
        
        if not host.is_isolated:
            return {
                "success": False,
                "message": f"Host {host.name} is not currently isolated"
            }
        
        # Create de-isolation event
        event = IsolationEvent(
            host_id=host.id,
            event_type="DEISOLATE",
            isolation_policy=host.isolation_policy.value if host.isolation_policy else None,
            triggered_by=triggered_by,
            initiated_by_user=initiated_by_user,
            dry_run=dry_run,
            timestamp=datetime.utcnow()
        )
        
        if dry_run:
            event.success = True
            self.db.add(event)
            self.db.commit()
            
            return {
                "success": True,
                "message": f"[DRY RUN] Would de-isolate host {host.name}",
                "data": {"host_id": host.id, "event_id": event.id}
            }
        
        # Create de-isolation task for agent
        task = Task(
            host_id=host.id,
            type="deisolate_host",
            parameters={"remove_all_ransomrun_rules": True},
            status="PENDING"
        )
        self.db.add(task)
        
        # Update host status
        previous_policy = host.isolation_policy
        host.is_isolated = False
        host.isolation_policy = IsolationPolicy.NONE
        host.isolation_ttl_minutes = None
        host.isolation_expires_at = None
        host.last_deisolated_at = datetime.utcnow()
        
        event.success = True
        event.isolation_policy = previous_policy.value if previous_policy else None
        self.db.add(event)
        self.db.commit()
        
        logger.info(f"Host {host.name} de-isolated successfully")
        
        return {
            "success": True,
            "message": f"Host {host.name} de-isolated successfully",
            "data": {
                "host_id": host.id,
                "previous_policy": previous_policy.value if previous_policy else None,
                "task_id": task.id,
                "event_id": event.id
            }
        }
    
    def check_ttl_expirations(self) -> Dict[str, Any]:
        """
        Check for hosts with expired isolation TTL and auto-unisolate them.
        Should be called periodically (e.g., every minute).
        
        Returns:
            Summary of auto-unisolated hosts
        """
        now = datetime.utcnow()
        
        # Find hosts with expired isolation
        expired_hosts = self.db.query(Host).filter(
            Host.is_isolated == True,
            Host.isolation_expires_at.isnot(None),
            Host.isolation_expires_at <= now
        ).all()
        
        if not expired_hosts:
            return {
                "success": True,
                "message": "No expired isolations found",
                "hosts_deisolated": 0
            }
        
        logger.info(f"Found {len(expired_hosts)} hosts with expired isolation TTL")
        
        deisolated = []
        for host in expired_hosts:
            result = self.deisolate_host(
                host=host,
                dry_run=False,
                triggered_by="ttl_expiry"
            )
            if result["success"]:
                deisolated.append(host.name)
        
        return {
            "success": True,
            "message": f"Auto-unisolated {len(deisolated)} hosts",
            "hosts_deisolated": len(deisolated),
            "hosts": deisolated
        }
    
    def get_isolation_status(self, host: Host) -> Dict[str, Any]:
        """
        Get current isolation status for a host.
        
        Args:
            host: Host to check
            
        Returns:
            Isolation status details
        """
        status = {
            "is_isolated": host.is_isolated,
            "policy": host.isolation_policy.value if host.isolation_policy else None,
            "ttl_minutes": host.isolation_ttl_minutes,
            "expires_at": host.isolation_expires_at.isoformat() if host.isolation_expires_at else None,
            "last_isolated_at": host.last_isolated_at.isoformat() if host.last_isolated_at else None,
            "last_deisolated_at": host.last_deisolated_at.isoformat() if host.last_deisolated_at else None,
            "quarantine_status": host.quarantine_status
        }
        
        # Check if TTL expired
        if host.is_isolated and host.isolation_expires_at:
            if datetime.utcnow() >= host.isolation_expires_at:
                status["ttl_expired"] = True
                status["should_auto_deisolate"] = True
        
        # Get recent isolation events
        recent_events = self.db.query(IsolationEvent).filter(
            IsolationEvent.host_id == host.id
        ).order_by(IsolationEvent.timestamp.desc()).limit(5).all()
        
        status["recent_events"] = [
            {
                "event_type": e.event_type,
                "policy": e.isolation_policy,
                "triggered_by": e.triggered_by,
                "timestamp": e.timestamp.isoformat(),
                "success": e.success
            }
            for e in recent_events
        ]
        
        return status
    
    # Helper methods
    
    def _get_firewall_rules_for_policy(self, policy: str, host: Host) -> Dict[str, Any]:
        """
        Get firewall rules that will be applied for a given policy.
        Used for escape hatch tracking.
        """
        server_ip = self._get_server_ip()
        
        rules = {
            "policy": policy,
            "rule_group": f"RansomRun_Isolation_{host.agent_id}",
            "rules": []
        }
        
        if policy == "FIREWALL_BLOCK":
            rules["rules"] = [
                {"name": "Block_All_Inbound", "direction": "in", "action": "block"},
                {"name": "Block_All_Outbound", "direction": "out", "action": "block"},
                {"name": "Allow_Server_Inbound", "direction": "in", "action": "allow", "remote_ip": server_ip}
            ]
        
        elif policy == "OUTBOUND_ONLY_BLOCK":
            rules["rules"] = [
                {"name": "Block_All_Outbound", "direction": "out", "action": "block"},
                {"name": "Allow_Server_Outbound", "direction": "out", "action": "allow", "remote_ip": server_ip}
            ]
        
        elif policy == "RANSOMRUN_CONTROLLED":
            rules["rules"] = [
                {"name": "Block_All_Outbound", "direction": "out", "action": "block"},
                {"name": "Block_All_Inbound", "direction": "in", "action": "block"},
                {"name": "Allow_Server", "direction": "both", "action": "allow", "remote_ip": server_ip},
                {"name": "Allow_DNS", "direction": "out", "action": "allow", "port": 53}
            ]
        
        elif policy == "HYBRID":
            rules["rules"] = [
                {"name": "Block_All_Inbound", "direction": "in", "action": "block"},
                {"name": "Block_All_Outbound", "direction": "out", "action": "block"},
                {"name": "Allow_Server", "direction": "both", "action": "allow", "remote_ip": server_ip},
                {"name": "Disable_NIC_Fallback", "action": "disable_adapter", "condition": "if_firewall_fails"}
            ]
        
        elif policy == "SEGMENT_QUARANTINE_SIM":
            rules["rules"] = [
                {"name": "Quarantine_Tag", "action": "tag", "tag": "QUARANTINE"},
                {"name": "Block_Lateral", "direction": "out", "action": "block", "remote_subnet": "private"},
                {"name": "Allow_Server", "direction": "both", "action": "allow", "remote_ip": server_ip}
            ]
        
        return rules
    
    def _get_server_ip(self) -> str:
        """Get the RansomRun server IP address."""
        # In production, this would be from config
        # For now, return localhost
        return "127.0.0.1"
