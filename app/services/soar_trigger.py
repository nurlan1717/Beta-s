"""SOAR Trigger Service for RansomRun platform.

This module evaluates ELK alerts and triggers appropriate response playbooks
based on severity, MITRE tactics, and detection patterns.

Trigger conditions:
- severity >= HIGH (41+)
- rule.threat.tactic contains "impact" or "defense-evasion"
- mass file rename detected
- vssadmin or wbadmin execution detected
- ransomware-related rule tags
"""

from typing import Optional, List, Dict, Any
from datetime import datetime


# Ransomware-related detection patterns
RANSOMWARE_PATTERNS = [
    'vssadmin',
    'wbadmin',
    'bcdedit',
    'shadow copy',
    'volume shadow',
    'ransomware',
    'encrypt',
    'locked',
    '.locked',
    '.encrypted',
    'ransom note',
    'bitcoin',
    'decrypt',
]

# High-risk MITRE tactics that should trigger immediate response
HIGH_RISK_TACTICS = [
    'impact',
    'defense-evasion',
    'credential-access',
    'exfiltration',
    'lateral-movement',
]

# High-risk MITRE techniques (ransomware-related)
HIGH_RISK_TECHNIQUES = [
    'T1486',  # Data Encrypted for Impact
    'T1490',  # Inhibit System Recovery
    'T1489',  # Service Stop
    'T1491',  # Defacement
    'T1485',  # Data Destruction
    'T1561',  # Disk Wipe
    'T1529',  # System Shutdown/Reboot
    'T1562',  # Impair Defenses
]


class SOARTrigger:
    """Evaluates alerts and determines appropriate response actions."""
    
    def __init__(self, db_session=None):
        self.db = db_session
    
    def evaluate_alert(self, alert: Dict) -> Dict[str, Any]:
        """
        Evaluate an alert and determine if it should trigger a playbook.
        
        Returns:
            Dict with trigger decision and recommended actions
        """
        result = {
            'should_trigger': False,
            'trigger_reasons': [],
            'recommended_playbook': None,
            'recommended_actions': [],
            'priority': 'low',
            'alert_id': alert.get('id'),
            'endpoint': alert.get('endpoint') or alert.get('agent_name'),
        }
        
        severity = alert.get('severity', 0)
        severity_label = alert.get('severity_label', 'LOW').upper()
        mitre = alert.get('mitre', {})
        tactic = (mitre.get('tactic') or '').lower()
        technique = mitre.get('technique', '')
        rule_name = (alert.get('rule_name') or '').lower()
        description = (alert.get('rule_description') or '').lower()
        process = (alert.get('process') or '').lower()
        
        # Check severity threshold (HIGH or CRITICAL)
        if severity >= 41 or severity_label in ('HIGH', 'CRITICAL'):
            result['should_trigger'] = True
            result['trigger_reasons'].append(f'High severity alert: {severity_label} ({severity})')
            result['priority'] = 'high' if severity >= 71 else 'medium'
        
        # Check for high-risk tactics
        for risk_tactic in HIGH_RISK_TACTICS:
            if risk_tactic in tactic:
                result['should_trigger'] = True
                result['trigger_reasons'].append(f'High-risk tactic detected: {tactic}')
                result['priority'] = 'high'
                break
        
        # Check for high-risk techniques
        if technique in HIGH_RISK_TECHNIQUES:
            result['should_trigger'] = True
            result['trigger_reasons'].append(f'High-risk MITRE technique: {technique}')
            result['priority'] = 'critical' if technique in ['T1486', 'T1490'] else 'high'
        
        # Check for ransomware patterns in rule name, description, or process
        text_to_check = f"{rule_name} {description} {process}"
        for pattern in RANSOMWARE_PATTERNS:
            if pattern in text_to_check:
                result['should_trigger'] = True
                result['trigger_reasons'].append(f'Ransomware pattern detected: {pattern}')
                result['priority'] = 'critical'
                break
        
        # Determine recommended playbook and actions
        if result['should_trigger']:
            result['recommended_playbook'], result['recommended_actions'] = \
                self._get_recommended_response(alert, result['trigger_reasons'])
        
        return result
    
    def _get_recommended_response(
        self, 
        alert: Dict, 
        trigger_reasons: List[str]
    ) -> tuple:
        """Determine recommended playbook and actions based on alert context."""
        
        technique = alert.get('mitre', {}).get('technique', '')
        tactic = (alert.get('mitre', {}).get('tactic') or '').lower()
        severity = alert.get('severity', 0)
        
        # Default actions
        actions = []
        playbook = 'generic_incident_response'
        
        # Ransomware-specific response (T1486 - Data Encrypted for Impact)
        if technique == 'T1486' or 'encrypt' in str(alert).lower():
            playbook = 'ransomware_response'
            actions = [
                {'action': 'isolate_endpoint', 'priority': 1, 'description': 'Isolate endpoint from network'},
                {'action': 'kill_process', 'priority': 2, 'description': 'Terminate malicious process'},
                {'action': 'collect_artifacts', 'priority': 3, 'description': 'Collect forensic artifacts'},
                {'action': 'disable_user', 'priority': 4, 'description': 'Disable compromised user account'},
                {'action': 'start_recovery', 'priority': 5, 'description': 'Initiate recovery workflow'},
            ]
        
        # Recovery inhibition (T1490 - Inhibit System Recovery)
        elif technique == 'T1490' or 'vssadmin' in str(alert).lower():
            playbook = 'recovery_inhibition_response'
            actions = [
                {'action': 'isolate_endpoint', 'priority': 1, 'description': 'Isolate endpoint immediately'},
                {'action': 'kill_process', 'priority': 2, 'description': 'Terminate vssadmin/wbadmin'},
                {'action': 'preserve_shadows', 'priority': 3, 'description': 'Attempt to preserve remaining shadow copies'},
                {'action': 'collect_artifacts', 'priority': 4, 'description': 'Collect forensic evidence'},
            ]
        
        # Defense evasion
        elif 'defense-evasion' in tactic:
            playbook = 'defense_evasion_response'
            actions = [
                {'action': 'collect_artifacts', 'priority': 1, 'description': 'Collect forensic artifacts'},
                {'action': 'check_persistence', 'priority': 2, 'description': 'Check for persistence mechanisms'},
                {'action': 'restore_defenses', 'priority': 3, 'description': 'Restore disabled security controls'},
            ]
        
        # Impact tactics
        elif 'impact' in tactic:
            playbook = 'impact_response'
            actions = [
                {'action': 'isolate_endpoint', 'priority': 1, 'description': 'Isolate endpoint from network'},
                {'action': 'assess_damage', 'priority': 2, 'description': 'Assess scope of impact'},
                {'action': 'collect_artifacts', 'priority': 3, 'description': 'Collect forensic artifacts'},
                {'action': 'start_recovery', 'priority': 4, 'description': 'Begin recovery procedures'},
            ]
        
        # Credential access
        elif 'credential-access' in tactic:
            playbook = 'credential_theft_response'
            actions = [
                {'action': 'disable_user', 'priority': 1, 'description': 'Disable compromised accounts'},
                {'action': 'reset_passwords', 'priority': 2, 'description': 'Force password reset'},
                {'action': 'collect_artifacts', 'priority': 3, 'description': 'Collect forensic artifacts'},
                {'action': 'check_lateral', 'priority': 4, 'description': 'Check for lateral movement'},
            ]
        
        # High severity generic
        elif severity >= 71:
            playbook = 'critical_alert_response'
            actions = [
                {'action': 'isolate_endpoint', 'priority': 1, 'description': 'Isolate endpoint from network'},
                {'action': 'collect_artifacts', 'priority': 2, 'description': 'Collect forensic artifacts'},
                {'action': 'escalate', 'priority': 3, 'description': 'Escalate to senior analyst'},
            ]
        
        # Medium-high severity
        else:
            playbook = 'standard_investigation'
            actions = [
                {'action': 'collect_artifacts', 'priority': 1, 'description': 'Collect forensic artifacts'},
                {'action': 'investigate', 'priority': 2, 'description': 'Investigate alert context'},
            ]
        
        return playbook, actions
    
    def evaluate_alerts_batch(self, alerts: List[Dict]) -> List[Dict]:
        """Evaluate multiple alerts and return trigger decisions."""
        return [self.evaluate_alert(alert) for alert in alerts]
    
    def get_triggered_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Filter alerts that should trigger a playbook response."""
        results = self.evaluate_alerts_batch(alerts)
        return [r for r in results if r['should_trigger']]
    
    def get_priority_summary(self, alerts: List[Dict]) -> Dict[str, int]:
        """Get count of alerts by priority level."""
        results = self.evaluate_alerts_batch(alerts)
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for r in results:
            if r['should_trigger']:
                priority = r.get('priority', 'low')
                summary[priority] = summary.get(priority, 0) + 1
        return summary


def evaluate_alert_for_playbook(alert: Dict) -> Dict[str, Any]:
    """Convenience function to evaluate a single alert."""
    trigger = SOARTrigger()
    return trigger.evaluate_alert(alert)


def get_playbook_recommendations(alerts: List[Dict]) -> List[Dict]:
    """Get playbook recommendations for a list of alerts."""
    trigger = SOARTrigger()
    return trigger.get_triggered_alerts(alerts)
