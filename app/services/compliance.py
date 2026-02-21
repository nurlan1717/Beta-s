"""
Compliance / Regulatory Incident View Service
==============================================
Generates management-friendly and regulator-friendly incident reports
using existing simulation data.
"""

from datetime import datetime
from typing import Dict, Optional, List
from sqlalchemy.orm import Session

from ..models import (
    Run, RunEvent, Alert, AffectedFile, BusinessImpact,
    ComplianceReport, ReportType, EventType, BehaviorProfile
)


def generate_compliance_report(
    db: Session,
    run: Run,
    report_type: ReportType = ReportType.GENERIC,
    data_sensitivity: int = 3,
    personal_data_involved: Optional[bool] = None
) -> ComplianceReport:
    """
    Generate a compliance/regulatory incident report.
    
    Args:
        db: Database session
        run: The Run to report on
        report_type: Type of report (GDPR, Generic, etc.)
        data_sensitivity: 1-5 scale
        personal_data_involved: Override for personal data flag
        
    Returns:
        ComplianceReport with all sections populated
    """
    # Gather data
    events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.timestamp).all()
    alerts = db.query(Alert).filter(Alert.run_id == run.id).order_by(Alert.timestamp).all()
    affected_files = db.query(AffectedFile).filter(AffectedFile.run_id == run.id).all()
    business_impact = db.query(BusinessImpact).filter(BusinessImpact.run_id == run.id).first()
    behavior_profile = db.query(BehaviorProfile).filter(BehaviorProfile.run_id == run.id).first()
    
    # Calculate timeline
    incident_start = run.started_at
    incident_detection = alerts[0].timestamp if alerts else None
    
    # Find containment time (first response action)
    containment_time = None
    for event in events:
        if event.event_type == EventType.RESPONSE_EXECUTED:
            containment_time = event.timestamp
            break
    
    if not containment_time:
        containment_time = run.ended_at
    
    # Determine if personal data involved
    if personal_data_involved is None:
        # Heuristic: high sensitivity or certain business units
        personal_data_involved = data_sensitivity >= 4
        if business_impact and business_impact.business_unit in ["HR", "Finance", "Legal"]:
            personal_data_involved = True
    
    # Estimate data subjects affected
    data_subjects = _estimate_data_subjects(affected_files, data_sensitivity, personal_data_involved)
    
    # Determine risk to individuals
    risk_level = _assess_risk_to_individuals(
        data_sensitivity, 
        len(affected_files), 
        personal_data_involved,
        run
    )
    
    # Determine if notification required
    notification_required = _assess_notification_requirement(
        report_type,
        risk_level,
        data_subjects,
        personal_data_involved
    )
    
    # Generate summary
    summary = _generate_summary(run, events, alerts, affected_files, report_type)
    
    # Generate mitigation recommendations
    mitigation = _generate_mitigation(run, behavior_profile, events)
    
    # Check for existing report
    existing = db.query(ComplianceReport).filter(
        ComplianceReport.run_id == run.id,
        ComplianceReport.report_type == report_type
    ).first()
    
    if existing:
        existing.summary = summary
        existing.incident_start = incident_start
        existing.incident_detection = incident_detection
        existing.incident_containment = containment_time
        existing.data_subjects_affected_estimate = data_subjects
        existing.personal_data_involved = personal_data_involved
        existing.regulatory_notification_required = notification_required
        existing.risk_to_individuals = risk_level
        existing.mitigation_recommendations = mitigation
        existing.generated_at = datetime.utcnow()
        db.commit()
        return existing
    
    # Create new report
    report = ComplianceReport(
        run_id=run.id,
        report_type=report_type,
        summary=summary,
        incident_start=incident_start,
        incident_detection=incident_detection,
        incident_containment=containment_time,
        data_subjects_affected_estimate=data_subjects,
        personal_data_involved=personal_data_involved,
        regulatory_notification_required=notification_required,
        risk_to_individuals=risk_level,
        mitigation_recommendations=mitigation
    )
    
    db.add(report)
    db.commit()
    db.refresh(report)
    
    return report


def _estimate_data_subjects(
    affected_files: List[AffectedFile],
    data_sensitivity: int,
    personal_data: bool
) -> Optional[int]:
    """Estimate number of data subjects potentially affected."""
    if not personal_data:
        return None
    
    # Heuristic: each file could contain records for multiple subjects
    # Higher sensitivity = more records per file
    records_per_file = data_sensitivity * 10
    
    return len(affected_files) * records_per_file


def _assess_risk_to_individuals(
    data_sensitivity: int,
    file_count: int,
    personal_data: bool,
    run: Run
) -> str:
    """Assess risk level to individuals."""
    if not personal_data:
        return "None"
    
    risk_score = 0
    
    # Data sensitivity factor
    risk_score += data_sensitivity * 10
    
    # File count factor
    if file_count > 100:
        risk_score += 30
    elif file_count > 50:
        risk_score += 20
    elif file_count > 10:
        risk_score += 10
    
    # Scenario category factor
    if run.scenario:
        category = run.scenario.category.value if run.scenario.category else "crypto"
        if category in ["wiper", "exfil"]:
            risk_score += 20
        elif category == "crypto":
            risk_score += 10
    
    if risk_score >= 60:
        return "High"
    elif risk_score >= 30:
        return "Moderate"
    else:
        return "Low"


def _assess_notification_requirement(
    report_type: ReportType,
    risk_level: str,
    data_subjects: Optional[int],
    personal_data: bool
) -> bool:
    """Determine if regulatory notification would be required."""
    if not personal_data:
        return False
    
    if report_type == ReportType.GDPR:
        # GDPR: notify if risk to rights and freedoms
        if risk_level in ["High", "Moderate"]:
            return True
        if data_subjects and data_subjects > 100:
            return True
    
    elif report_type == ReportType.HIPAA:
        # HIPAA: notify if PHI breach affects 500+ individuals
        if data_subjects and data_subjects >= 500:
            return True
        if risk_level == "High":
            return True
    
    elif report_type == ReportType.PCI_DSS:
        # PCI: notify if cardholder data compromised
        if risk_level in ["High", "Moderate"]:
            return True
    
    else:
        # Generic: notify for high risk
        if risk_level == "High":
            return True
    
    return False


def _generate_summary(
    run: Run,
    events: List[RunEvent],
    alerts: List[Alert],
    affected_files: List[AffectedFile],
    report_type: ReportType
) -> str:
    """Generate incident summary text."""
    host_name = run.host.name if run.host else "Unknown Host"
    scenario_name = run.scenario.name if run.scenario else "Unknown Scenario"
    
    # Calculate duration
    duration_str = "Unknown"
    if run.started_at and run.ended_at:
        duration = (run.ended_at - run.started_at).total_seconds()
        if duration < 60:
            duration_str = f"{int(duration)} seconds"
        elif duration < 3600:
            duration_str = f"{int(duration / 60)} minutes"
        else:
            duration_str = f"{duration / 3600:.1f} hours"
    
    summary_parts = [
        f"## Incident Summary",
        f"",
        f"**Incident Type:** Ransomware Simulation ({scenario_name})",
        f"**Affected System:** {host_name}",
        f"**Duration:** {duration_str}",
        f"**Files Affected:** {len(affected_files)}",
        f"**Alerts Generated:** {len(alerts)}",
        f"",
        f"### Description",
        f"",
        f"A ransomware simulation was executed on {host_name} using the '{scenario_name}' scenario. "
    ]
    
    # Add scenario-specific details
    if run.scenario and run.scenario.category:
        category = run.scenario.category.value
        if category == "crypto":
            summary_parts.append(
                "The simulation involved file encryption/renaming operations, "
                "ransom note creation, and potential shadow copy deletion."
            )
        elif category == "wiper":
            summary_parts.append(
                "The simulation involved destructive file operations designed to "
                "simulate data destruction malware."
            )
        elif category == "exfil":
            summary_parts.append(
                "The simulation focused on data exfiltration preparation, "
                "including file staging and compression."
            )
        elif category == "locker":
            summary_parts.append(
                "The simulation involved screen locker behavior with "
                "ransom note display."
            )
    
    # Add outcome
    summary_parts.extend([
        f"",
        f"### Outcome",
        f"",
        f"The simulation completed with status: **{run.status.value}**. "
    ])
    
    # Add response info
    response_events = [e for e in events if e.event_type == EventType.RESPONSE_EXECUTED]
    if response_events:
        summary_parts.append(
            f"{len(response_events)} automated response action(s) were triggered."
        )
    else:
        summary_parts.append(
            "No automated response actions were triggered during this simulation."
        )
    
    return "\n".join(summary_parts)


def _generate_mitigation(
    run: Run,
    behavior_profile: Optional[BehaviorProfile],
    events: List[RunEvent]
) -> str:
    """Generate mitigation and prevention recommendations."""
    recommendations = [
        "## Mitigation & Prevention Recommendations",
        ""
    ]
    
    # Based on behavior profile
    if behavior_profile and behavior_profile.dna_vector:
        dna = behavior_profile.dna_vector
        
        if dna.get("recovery_inhibition", 0) > 0.5:
            recommendations.append(
                "- **Protect Backup Systems:** Implement immutable backups and "
                "monitor for shadow copy deletion attempts (T1490)."
            )
        
        if dna.get("encryption", 0) > 0.5:
            recommendations.append(
                "- **File Integrity Monitoring:** Deploy FIM solutions to detect "
                "mass file modifications and encryption patterns."
            )
        
        if dna.get("persistence", 0) > 0.5:
            recommendations.append(
                "- **Persistence Detection:** Monitor registry run keys and "
                "scheduled tasks for unauthorized modifications."
            )
        
        if dna.get("exfil", 0) > 0.5:
            recommendations.append(
                "- **Data Loss Prevention:** Implement DLP controls to detect "
                "and prevent unauthorized data staging and exfiltration."
            )
    
    # General recommendations
    recommendations.extend([
        "",
        "### General Recommendations",
        "",
        "- **User Training:** Conduct regular security awareness training "
        "focusing on phishing and social engineering.",
        "",
        "- **Endpoint Protection:** Ensure EDR/antivirus solutions are "
        "up-to-date and properly configured.",
        "",
        "- **Network Segmentation:** Limit lateral movement potential through "
        "proper network segmentation.",
        "",
        "- **Incident Response Plan:** Review and update incident response "
        "procedures based on lessons learned.",
        "",
        "- **Backup Verification:** Regularly test backup restoration "
        "procedures to ensure recoverability."
    ])
    
    return "\n".join(recommendations)


def get_compliance_report_for_run(
    db: Session, 
    run_id: int, 
    report_type: Optional[ReportType] = None
) -> Optional[ComplianceReport]:
    """Get compliance report for a specific run."""
    query = db.query(ComplianceReport).filter(ComplianceReport.run_id == run_id)
    if report_type:
        query = query.filter(ComplianceReport.report_type == report_type)
    return query.first()


def get_all_compliance_reports(db: Session, limit: int = 50) -> List[ComplianceReport]:
    """Get all compliance reports."""
    return db.query(ComplianceReport).order_by(
        ComplianceReport.generated_at.desc()
    ).limit(limit).all()


def format_report_for_export(report: ComplianceReport, run: Run) -> str:
    """Format report for text/HTML export."""
    lines = [
        "=" * 60,
        "INCIDENT COMPLIANCE REPORT",
        "=" * 60,
        "",
        f"Report Type: {report.report_type.value}",
        f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') if report.generated_at else 'N/A'}",
        f"Run ID: {run.id}",
        "",
        "-" * 60,
        "TIMELINE",
        "-" * 60,
        "",
        f"Incident Start: {report.incident_start.strftime('%Y-%m-%d %H:%M:%S UTC') if report.incident_start else 'N/A'}",
        f"Detection Time: {report.incident_detection.strftime('%Y-%m-%d %H:%M:%S UTC') if report.incident_detection else 'N/A'}",
        f"Containment Time: {report.incident_containment.strftime('%Y-%m-%d %H:%M:%S UTC') if report.incident_containment else 'N/A'}",
        "",
        "-" * 60,
        "DATA IMPACT ASSESSMENT",
        "-" * 60,
        "",
        f"Personal Data Involved: {'Yes' if report.personal_data_involved else 'No'}",
        f"Data Subjects Affected: {report.data_subjects_affected_estimate or 'N/A'}",
        f"Risk to Individuals: {report.risk_to_individuals or 'N/A'}",
        f"Regulatory Notification Required: {'Yes' if report.regulatory_notification_required else 'No'}",
        "",
        "-" * 60,
        "SUMMARY",
        "-" * 60,
        "",
        report.summary or "No summary available.",
        "",
        "-" * 60,
        "MITIGATION RECOMMENDATIONS",
        "-" * 60,
        "",
        report.mitigation_recommendations or "No recommendations available.",
        "",
        "=" * 60,
        "END OF REPORT",
        "=" * 60
    ]
    
    return "\n".join(lines)
