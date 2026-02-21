"""
Lessons Learned Generator Module.

Analyzes run data to generate structured lessons learned reports
with metrics, findings, and action items.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from ..models import (
    Run, Task, Alert, RunEvent, EventType, IRPhase, TaskStatus, RunStatus,
    LessonsLearned, LessonsActionItem, ActionItemPriority, ActionItemStatus,
    AffectedFile, IOC
)


class LessonsLearnedGenerator:
    """
    Generates structured lessons learned from run data.
    
    Analyzes timing metrics, events, and outcomes to produce:
    - Summary of the incident
    - What went well / what went wrong
    - Recommended action items
    """
    
    # MITRE technique descriptions
    MITRE_DESCRIPTIONS = {
        "T1486": "Data Encrypted for Impact",
        "T1490": "Inhibit System Recovery",
        "T1059": "Command and Scripting Interpreter",
        "T1547": "Boot or Logon Autostart Execution",
        "T1053": "Scheduled Task/Job",
        "T1055": "Process Injection",
        "T1083": "File and Directory Discovery",
        "T1082": "System Information Discovery",
        "T1041": "Exfiltration Over C2 Channel",
        "T1048": "Exfiltration Over Alternative Protocol",
    }
    
    def __init__(self, db: Session, run_id: int):
        self.db = db
        self.run_id = run_id
        self.run: Optional[Run] = None
        self.metrics: Dict[str, Any] = {}
        self.findings: Dict[str, List[str]] = {
            "went_well": [],
            "went_wrong": []
        }
        self.action_items: List[Dict] = []
        
    def generate(self) -> Dict[str, Any]:
        """
        Generate complete lessons learned report.
        
        Returns:
            Dictionary containing lessons learned data
        """
        # Load run
        self.run = self.db.query(Run).filter(Run.id == self.run_id).first()
        if not self.run:
            return {"error": "Run not found", "run_id": self.run_id}
        
        # Calculate metrics
        self._calculate_timing_metrics()
        self._calculate_impact_metrics()
        self._collect_mitre_techniques()
        
        # Analyze findings
        self._analyze_detection()
        self._analyze_containment()
        self._analyze_recovery()
        
        # Generate action items
        self._generate_action_items()
        
        # Build summary
        summary = self._build_summary()
        
        return {
            "run_id": self.run_id,
            "summary": summary,
            "what_went_well": self.findings["went_well"],
            "what_went_wrong": self.findings["went_wrong"],
            "metrics": self.metrics,
            "action_items": self.action_items,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def save(self) -> LessonsLearned:
        """
        Generate and save lessons learned to database.
        
        Returns:
            LessonsLearned model instance
        """
        data = self.generate()
        
        if "error" in data:
            raise ValueError(data["error"])
        
        # Check if lessons already exist for this run
        existing = self.db.query(LessonsLearned).filter(
            LessonsLearned.run_id == self.run_id
        ).first()
        
        if existing:
            # Update existing
            existing.summary = data["summary"]
            existing.what_went_well = data["what_went_well"]
            existing.what_went_wrong = data["what_went_wrong"]
            existing.time_to_detect_seconds = self.metrics.get("ttd_seconds")
            existing.time_to_contain_seconds = self.metrics.get("ttc_seconds")
            existing.time_to_recover_seconds = self.metrics.get("ttr_seconds")
            existing.total_duration_seconds = self.metrics.get("total_duration_seconds")
            existing.affected_files_count = self.metrics.get("affected_files", 0)
            existing.affected_endpoints_count = self.metrics.get("affected_endpoints", 1)
            existing.high_severity_alerts_count = self.metrics.get("high_severity_alerts", 0)
            existing.total_alerts_count = self.metrics.get("total_alerts", 0)
            existing.mitre_techniques = self.metrics.get("mitre_techniques", [])
            existing.updated_at = datetime.utcnow()
            
            # Delete old action items
            self.db.query(LessonsActionItem).filter(
                LessonsActionItem.lessons_learned_id == existing.id
            ).delete()
            
            lessons = existing
        else:
            # Create new
            lessons = LessonsLearned(
                run_id=self.run_id,
                summary=data["summary"],
                what_went_well=data["what_went_well"],
                what_went_wrong=data["what_went_wrong"],
                time_to_detect_seconds=self.metrics.get("ttd_seconds"),
                time_to_contain_seconds=self.metrics.get("ttc_seconds"),
                time_to_recover_seconds=self.metrics.get("ttr_seconds"),
                total_duration_seconds=self.metrics.get("total_duration_seconds"),
                affected_files_count=self.metrics.get("affected_files", 0),
                affected_endpoints_count=self.metrics.get("affected_endpoints", 1),
                high_severity_alerts_count=self.metrics.get("high_severity_alerts", 0),
                total_alerts_count=self.metrics.get("total_alerts", 0),
                mitre_techniques=self.metrics.get("mitre_techniques", [])
            )
            self.db.add(lessons)
            self.db.flush()  # Get the ID
        
        # Add action items
        for item_data in self.action_items:
            action_item = LessonsActionItem(
                run_id=self.run_id,
                lessons_learned_id=lessons.id,
                item=item_data["item"],
                priority=ActionItemPriority(item_data["priority"]),
                category=item_data.get("category"),
                owner=item_data.get("owner"),
                status=ActionItemStatus.OPEN
            )
            self.db.add(action_item)
        
        self.db.commit()
        return lessons
    
    def _calculate_timing_metrics(self):
        """Calculate TTD, TTC, TTR metrics."""
        if not self.run.started_at:
            return
        
        run_start = self.run.started_at
        run_end = self.run.ended_at or datetime.utcnow()
        
        # Total duration
        self.metrics["total_duration_seconds"] = (run_end - run_start).total_seconds()
        
        # Time to Detect (TTD): First alert - run start
        first_alert = self.db.query(Alert).filter(
            Alert.run_id == self.run_id
        ).order_by(Alert.timestamp).first()
        
        if first_alert and first_alert.timestamp:
            ttd = (first_alert.timestamp - run_start).total_seconds()
            self.metrics["ttd_seconds"] = max(0, ttd)
            self.metrics["first_alert_time"] = first_alert.timestamp.isoformat()
        else:
            self.metrics["ttd_seconds"] = None
            self.metrics["ttd_note"] = "No alerts detected"
        
        # Time to Contain (TTC): First containment event - first alert
        containment_events = self.db.query(RunEvent).filter(
            RunEvent.run_id == self.run_id,
            RunEvent.event_type.in_([
                EventType.HOST_ISOLATED,
                EventType.CONTAINMENT_COMPLETED,
                EventType.PATH_BLOCKED,
                EventType.FILE_QUARANTINED
            ])
        ).order_by(RunEvent.timestamp).first()
        
        if containment_events and containment_events.timestamp:
            if first_alert and first_alert.timestamp:
                ttc = (containment_events.timestamp - first_alert.timestamp).total_seconds()
                self.metrics["ttc_seconds"] = max(0, ttc)
            self.metrics["containment_time"] = containment_events.timestamp.isoformat()
        else:
            self.metrics["ttc_seconds"] = None
            self.metrics["ttc_note"] = "No containment action recorded"
        
        # Time to Recover (TTR): Recovery completed - containment
        recovery_events = self.db.query(RunEvent).filter(
            RunEvent.run_id == self.run_id,
            RunEvent.event_type.in_([
                EventType.RECOVERY_COMPLETED,
                EventType.HOST_NETWORK_RESTORED,
                EventType.ROLLBACK_COMPLETED
            ])
        ).order_by(RunEvent.timestamp).first()
        
        if recovery_events and recovery_events.timestamp:
            if containment_events and containment_events.timestamp:
                ttr = (recovery_events.timestamp - containment_events.timestamp).total_seconds()
                self.metrics["ttr_seconds"] = max(0, ttr)
            self.metrics["recovery_time"] = recovery_events.timestamp.isoformat()
        else:
            self.metrics["ttr_seconds"] = None
            self.metrics["ttr_note"] = "No recovery completion recorded"
    
    def _calculate_impact_metrics(self):
        """Calculate impact metrics: files, endpoints, alerts."""
        # Affected files
        affected_files = self.db.query(AffectedFile).filter(
            AffectedFile.run_id == self.run_id
        ).count()
        self.metrics["affected_files"] = affected_files
        
        # IOCs collected
        iocs = self.db.query(IOC).filter(IOC.run_id == self.run_id).count()
        self.metrics["iocs_collected"] = iocs
        
        # Alerts
        alerts = self.db.query(Alert).filter(Alert.run_id == self.run_id).all()
        self.metrics["total_alerts"] = len(alerts)
        self.metrics["high_severity_alerts"] = sum(1 for a in alerts if a.severity >= 8)
        self.metrics["critical_alerts"] = sum(1 for a in alerts if a.severity >= 12)
        
        # Affected endpoints (for now, just the run's host)
        self.metrics["affected_endpoints"] = 1
    
    def _collect_mitre_techniques(self):
        """Collect MITRE ATT&CK techniques from alerts and scenario."""
        techniques = set()
        
        # From alerts (using rule_id mapping)
        rule_mitre_map = {
            "RR-2001": "T1486", "RR-2002": "T1486",
            "RR-2003": "T1490", "RR-2004": "T1490",
            "RR-2005": "T1059", "RR-2006": "T1547",
            "RR-2007": "T1053", "RR-2008": "T1055",
        }
        
        alerts = self.db.query(Alert).filter(Alert.run_id == self.run_id).all()
        for alert in alerts:
            if alert.rule_id in rule_mitre_map:
                techniques.add(rule_mitre_map[alert.rule_id])
        
        # From scenario config
        if self.run.scenario and self.run.scenario.config:
            scenario_techniques = self.run.scenario.config.get("mitre_techniques", [])
            techniques.update(scenario_techniques)
        
        self.metrics["mitre_techniques"] = list(techniques)
        self.metrics["mitre_descriptions"] = [
            {"id": t, "name": self.MITRE_DESCRIPTIONS.get(t, "Unknown")}
            for t in techniques
        ]
    
    def _analyze_detection(self):
        """Analyze detection performance."""
        ttd = self.metrics.get("ttd_seconds")
        
        if ttd is not None:
            if ttd < 30:
                self.findings["went_well"].append(
                    f"Fast detection: First alert triggered within {ttd:.0f} seconds"
                )
            elif ttd < 120:
                self.findings["went_well"].append(
                    f"Detection occurred within acceptable timeframe ({ttd:.0f}s)"
                )
            else:
                self.findings["went_wrong"].append(
                    f"Slow detection: {ttd/60:.1f} minutes to first alert"
                )
        else:
            self.findings["went_wrong"].append(
                "No detection alerts were generated during the simulation"
            )
        
        # Alert quality
        total_alerts = self.metrics.get("total_alerts", 0)
        high_sev = self.metrics.get("high_severity_alerts", 0)
        
        if total_alerts > 0:
            if high_sev > 0:
                self.findings["went_well"].append(
                    f"High-severity alerts generated: {high_sev} of {total_alerts} total"
                )
            else:
                self.findings["went_wrong"].append(
                    "No high-severity alerts - detection rules may need tuning"
                )
    
    def _analyze_containment(self):
        """Analyze containment actions."""
        ttc = self.metrics.get("ttc_seconds")
        
        # Check for containment events
        containment_events = self.db.query(RunEvent).filter(
            RunEvent.run_id == self.run_id,
            RunEvent.event_type.in_([
                EventType.HOST_ISOLATED,
                EventType.CONTAINMENT_COMPLETED,
                EventType.PATH_BLOCKED,
                EventType.FILE_QUARANTINED
            ])
        ).count()
        
        if containment_events > 0:
            self.findings["went_well"].append(
                f"Containment actions executed: {containment_events} actions taken"
            )
            
            if ttc is not None and ttc < 60:
                self.findings["went_well"].append(
                    f"Quick containment response: {ttc:.0f} seconds after detection"
                )
            elif ttc is not None and ttc > 300:
                self.findings["went_wrong"].append(
                    f"Slow containment: {ttc/60:.1f} minutes after detection"
                )
        else:
            self.findings["went_wrong"].append(
                "No containment actions were executed during the incident"
            )
        
        # Check for isolation failures
        isolation_failures = self.db.query(RunEvent).filter(
            RunEvent.run_id == self.run_id,
            RunEvent.event_type == EventType.HOST_ISOLATION_FAILED
        ).count()
        
        if isolation_failures > 0:
            self.findings["went_wrong"].append(
                f"Host isolation failed {isolation_failures} time(s)"
            )
    
    def _analyze_recovery(self):
        """Analyze recovery actions."""
        ttr = self.metrics.get("ttr_seconds")
        
        recovery_events = self.db.query(RunEvent).filter(
            RunEvent.run_id == self.run_id,
            RunEvent.event_type.in_([
                EventType.RECOVERY_COMPLETED,
                EventType.HOST_NETWORK_RESTORED,
                EventType.ROLLBACK_COMPLETED
            ])
        ).count()
        
        if recovery_events > 0:
            self.findings["went_well"].append(
                f"Recovery completed successfully: {recovery_events} recovery actions"
            )
            
            if ttr is not None and ttr < 300:
                self.findings["went_well"].append(
                    f"Fast recovery: {ttr/60:.1f} minutes from containment to recovery"
                )
        else:
            self.findings["went_wrong"].append(
                "No formal recovery process was executed"
            )
        
        # Check for recovery failures
        recovery_failures = self.db.query(RunEvent).filter(
            RunEvent.run_id == self.run_id,
            RunEvent.event_type.in_([
                EventType.RECOVERY_FAILED,
                EventType.HOST_RESTORE_FAILED,
                EventType.ROLLBACK_FAILED
            ])
        ).count()
        
        if recovery_failures > 0:
            self.findings["went_wrong"].append(
                f"Recovery failures occurred: {recovery_failures} failed attempts"
            )
    
    def _generate_action_items(self):
        """Generate recommended action items based on findings."""
        # Detection-related items
        if self.metrics.get("ttd_seconds") is None:
            self.action_items.append({
                "item": "Review and improve detection rules - no alerts generated during simulation",
                "priority": "CRITICAL",
                "category": "detection",
                "owner": "SOC Team"
            })
        elif self.metrics.get("ttd_seconds", 0) > 120:
            self.action_items.append({
                "item": "Tune detection rules to reduce time-to-detect below 2 minutes",
                "priority": "HIGH",
                "category": "detection",
                "owner": "Detection Engineering"
            })
        
        # Containment items
        if self.metrics.get("ttc_seconds") is None:
            self.action_items.append({
                "item": "Implement automated containment playbooks for faster response",
                "priority": "HIGH",
                "category": "containment",
                "owner": "IR Team"
            })
        
        # Recovery items
        if self.metrics.get("ttr_seconds") is None:
            self.action_items.append({
                "item": "Document and test recovery procedures",
                "priority": "MEDIUM",
                "category": "recovery",
                "owner": "IT Operations"
            })
        
        # General recommendations
        self.action_items.append({
            "item": "Schedule follow-up tabletop exercise within 30 days",
            "priority": "MEDIUM",
            "category": "training",
            "owner": "Security Manager"
        })
        
        self.action_items.append({
            "item": "Update incident response runbooks with lessons from this simulation",
            "priority": "MEDIUM",
            "category": "process",
            "owner": "IR Team"
        })
        
        # MITRE-specific recommendations
        techniques = self.metrics.get("mitre_techniques", [])
        if "T1486" in techniques:
            self.action_items.append({
                "item": "Verify backup integrity and test restore procedures for ransomware scenarios",
                "priority": "HIGH",
                "category": "recovery",
                "owner": "Backup Admin"
            })
        
        if "T1490" in techniques:
            self.action_items.append({
                "item": "Implement additional protection for Volume Shadow Copies",
                "priority": "HIGH",
                "category": "prevention",
                "owner": "Endpoint Team"
            })
        
        # Ensure minimum 5 action items
        while len(self.action_items) < 5:
            self.action_items.append({
                "item": "Review and update security awareness training materials",
                "priority": "LOW",
                "category": "training",
                "owner": "Security Team"
            })
    
    def _build_summary(self) -> str:
        """Build executive summary paragraph."""
        lines = []
        
        # Opening
        scenario_name = self.run.scenario.name if self.run.scenario else "Unknown Scenario"
        host_name = self.run.host.name if self.run.host else "Unknown Host"
        lines.append(
            f"This lessons learned report summarizes the ransomware simulation "
            f"'{scenario_name}' executed on endpoint '{host_name}'."
        )
        
        # Duration
        duration = self.metrics.get("total_duration_seconds")
        if duration:
            if duration < 60:
                lines.append(f"The simulation ran for {duration:.0f} seconds.")
            else:
                lines.append(f"The simulation ran for {duration/60:.1f} minutes.")
        
        # Detection
        ttd = self.metrics.get("ttd_seconds")
        if ttd is not None:
            lines.append(f"Detection occurred {ttd:.0f} seconds after simulation start.")
        else:
            lines.append("No detection alerts were generated during this simulation.")
        
        # Impact
        affected = self.metrics.get("affected_files", 0)
        alerts = self.metrics.get("total_alerts", 0)
        lines.append(
            f"Impact: {affected} files affected, {alerts} security alerts generated."
        )
        
        # MITRE
        techniques = self.metrics.get("mitre_techniques", [])
        if techniques:
            lines.append(
                f"MITRE ATT&CK techniques observed: {', '.join(techniques)}."
            )
        
        # Key findings count
        well_count = len(self.findings["went_well"])
        wrong_count = len(self.findings["went_wrong"])
        lines.append(
            f"Key findings: {well_count} positive observations, "
            f"{wrong_count} areas for improvement identified."
        )
        
        # Action items
        lines.append(
            f"{len(self.action_items)} action items have been generated for follow-up."
        )
        
        return " ".join(lines)


def generate_lessons_learned(db: Session, run_id: int, save: bool = True) -> Dict[str, Any]:
    """
    Convenience function to generate lessons learned for a run.
    
    Args:
        db: Database session
        run_id: ID of the run
        save: Whether to save to database
        
    Returns:
        Dictionary containing lessons learned data
    """
    generator = LessonsLearnedGenerator(db, run_id)
    
    if save:
        lessons = generator.save()
        data = generator.generate()
        data["lessons_learned_id"] = lessons.id
        return data
    else:
        return generator.generate()
