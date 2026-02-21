"""Ransomware Behavior Detection Rules for RansomRun platform.

This module implements Sysmon-based detection rules for ransomware behaviors.
Each rule processes Elasticsearch events and returns normalized alerts.

Sysmon Event IDs Reference:
    1  = Process Create
    3  = Network Connection
    10 = Process Access
    11 = File Create
    12 = Registry Event (Create/Delete)
    13 = Registry Value Set
    22 = DNS Query

Severity Mapping (RansomRun platform style):
    LOW      = 3
    MEDIUM   = 6
    HIGH     = 10
    CRITICAL = 15

Note: severity >= 10 means high severity in the platform.
"""

import hashlib
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field


@dataclass
class DetectionAlert:
    """Normalized alert format for RansomRun platform."""
    id: str                          # Stable fingerprint/ID
    ts: str                          # @timestamp ISO format
    host: str                        # host.name
    user: Optional[str]              # user.name if exists
    severity: str                    # LOW|MEDIUM|HIGH|CRITICAL
    severity_num: int                # 3|6|10|15
    rule_id: str                     # RR-200X
    rule_name: str                   # Human readable name
    mitre: List[str]                 # MITRE technique IDs
    summary: str                     # Alert summary
    raw: Dict[str, Any]              # Subset of _source + extracted fields
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'ts': self.ts,
            'host': self.host,
            'user': self.user,
            'severity': self.severity,
            'severity_num': self.severity_num,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'mitre': self.mitre,
            'summary': self.summary,
            'raw': self.raw
        }


class DetectionRule(ABC):
    """Base class for detection rules."""
    
    rule_id: str = "RR-0000"
    rule_name: str = "Base Rule"
    mitre_techniques: List[str] = []
    description: str = ""
    
    # Sysmon event IDs this rule processes
    event_ids: List[int] = []
    
    @abstractmethod
    def evaluate(self, event: Dict, context: 'DetectionContext') -> Optional[DetectionAlert]:
        """
        Evaluate a single event against this rule.
        
        Args:
            event: Elasticsearch hit (_source + metadata)
            context: Shared context for correlation and deduplication
        
        Returns:
            DetectionAlert if rule triggers, None otherwise
        """
        pass
    
    def _extract_source(self, event: Dict) -> Dict:
        """Extract _source from ES hit."""
        return event.get('_source', event)
    
    def _get_field(self, source: Dict, field_path: str, default=None):
        """Safely get nested field using dot notation."""
        keys = field_path.split('.')
        value = source
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value
    
    def _generate_fingerprint(self, *args) -> str:
        """Generate stable fingerprint for deduplication."""
        data = '|'.join(str(a) for a in args if a)
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _create_alert(
        self,
        source: Dict,
        severity: str,
        severity_num: int,
        summary: str,
        fingerprint_parts: List[Any],
        extra_raw: Dict = None
    ) -> DetectionAlert:
        """Helper to create normalized alert."""
        raw_data = {
            'process_name': self._get_field(source, 'process.name'),
            'process_pid': self._get_field(source, 'process.pid'),
            'process_entity_id': self._get_field(source, 'process.entity_id'),
            'process_command_line': self._get_field(source, 'process.command_line'),
            'process_parent_name': self._get_field(source, 'process.parent.name'),
            'process_parent_command_line': self._get_field(source, 'process.parent.command_line'),
            'file_path': self._get_field(source, 'file.path'),
            'file_name': self._get_field(source, 'file.name'),
            'destination_ip': self._get_field(source, 'destination.ip'),
            'destination_port': self._get_field(source, 'destination.port'),
            'event_id': self._get_field(source, 'winlog.event_id'),
            'event_action': self._get_field(source, 'event.action'),
        }
        
        if extra_raw:
            raw_data.update(extra_raw)
        
        # Remove None values
        raw_data = {k: v for k, v in raw_data.items() if v is not None}
        
        return DetectionAlert(
            id=self._generate_fingerprint(*fingerprint_parts),
            ts=self._get_field(source, '@timestamp', datetime.utcnow().isoformat()),
            host=self._get_field(source, 'host.name', 'unknown'),
            user=self._get_field(source, 'user.name'),
            severity=severity,
            severity_num=severity_num,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            mitre=self.mitre_techniques,
            summary=summary,
            raw=raw_data
        )


@dataclass
class DetectionContext:
    """Shared context for detection rules - correlation and deduplication."""
    
    # Deduplication: fingerprints seen in current window
    seen_fingerprints: Set[str] = field(default_factory=set)
    fingerprint_ttl_seconds: int = 300  # 5 minute TTL
    
    # Correlation windows: host -> process -> events
    # Used for multi-event correlations (e.g., Office -> Script -> Network)
    correlation_windows: Dict[str, Dict[str, List[Dict]]] = field(default_factory=dict)
    correlation_ttl_seconds: int = 300  # 5 minute correlation window
    
    # Rate tracking: (host, process) -> event timestamps
    rate_windows: Dict[str, List[datetime]] = field(default_factory=dict)
    rate_window_seconds: int = 60
    
    def is_duplicate(self, fingerprint: str) -> bool:
        """Check if fingerprint was already seen."""
        return fingerprint in self.seen_fingerprints
    
    def mark_seen(self, fingerprint: str):
        """Mark fingerprint as seen."""
        self.seen_fingerprints.add(fingerprint)
    
    def add_to_correlation(self, host: str, process_id: str, event: Dict):
        """Add event to correlation window."""
        if host not in self.correlation_windows:
            self.correlation_windows[host] = {}
        if process_id not in self.correlation_windows[host]:
            self.correlation_windows[host][process_id] = []
        self.correlation_windows[host][process_id].append(event)
    
    def get_correlated_events(self, host: str, process_id: str) -> List[Dict]:
        """Get events for correlation."""
        return self.correlation_windows.get(host, {}).get(process_id, [])
    
    def track_rate(self, key: str, timestamp: datetime) -> int:
        """Track event rate and return count in window."""
        if key not in self.rate_windows:
            self.rate_windows[key] = []
        
        # Add current timestamp
        self.rate_windows[key].append(timestamp)
        
        # Clean old entries
        cutoff = datetime.utcnow() - timedelta(seconds=self.rate_window_seconds)
        self.rate_windows[key] = [
            ts for ts in self.rate_windows[key] 
            if ts > cutoff
        ]
        
        return len(self.rate_windows[key])


# =============================================================================
# RULE RR-2001: Mass File Create/Rename Spike (Possible Encryption)
# =============================================================================
# 
# KQL Example:
#   event.provider:"Microsoft-Windows-Sysmon" AND winlog.event_id:11
#
# JSON DSL:
#   {
#     "query": {
#       "bool": {
#         "must": [
#           {"term": {"event.provider": "Microsoft-Windows-Sysmon"}},
#           {"term": {"winlog.event_id": 11}}
#         ]
#       }
#     }
#   }
#
# Detection Logic:
#   - Track file create events (Sysmon Event ID 11) per host+process
#   - Trigger if > N events in 60 seconds
#   - N=50 -> HIGH, N=200 -> CRITICAL
# =============================================================================

class RR_2001_MassFileCreate(DetectionRule):
    """Detect mass file creation/rename indicating possible encryption."""
    
    rule_id = "RR-2001"
    rule_name = "Mass File Create/Rename Spike (Possible Encryption)"
    mitre_techniques = ["T1486"]
    description = "Detects high rate of file creation events that may indicate ransomware encryption activity"
    event_ids = [11]  # Sysmon FileCreate
    
    # Thresholds
    THRESHOLD_HIGH = 50
    THRESHOLD_CRITICAL = 200
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = self._extract_source(event)
        
        # Check event ID
        event_id = self._get_field(source, 'winlog.event_id')
        if event_id != 11:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        process_name = self._get_field(source, 'process.name', 'unknown')
        process_entity_id = self._get_field(source, 'process.entity_id', '')
        
        # Track rate
        rate_key = f"{host}|{process_entity_id or process_name}"
        try:
            ts_str = self._get_field(source, '@timestamp')
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00').replace('+00:00', ''))
        except:
            ts = datetime.utcnow()
        
        count = context.track_rate(rate_key, ts)
        
        # Check thresholds
        if count < self.THRESHOLD_HIGH:
            return None
        
        # Determine severity
        if count >= self.THRESHOLD_CRITICAL:
            severity = "CRITICAL"
            severity_num = 15
        else:
            severity = "HIGH"
            severity_num = 10
        
        # Generate fingerprint (dedupe per host+process per minute)
        minute_bucket = ts.strftime('%Y%m%d%H%M')
        fingerprint = self._generate_fingerprint(
            self.rule_id, host, process_entity_id or process_name, minute_bucket
        )
        
        if context.is_duplicate(fingerprint):
            return None
        
        context.mark_seen(fingerprint)
        
        file_path = self._get_field(source, 'file.path', '')
        summary = f"Mass file creation detected: {count} files in 60s by {process_name} on {host}"
        
        return self._create_alert(
            source=source,
            severity=severity,
            severity_num=severity_num,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, process_entity_id, minute_bucket],
            extra_raw={'file_count': count, 'sample_file': file_path}
        )


# =============================================================================
# RULE RR-2002: Shadow Copy / Backup Deletion Commands
# =============================================================================
#
# KQL Example:
#   event.provider:"Microsoft-Windows-Sysmon" AND winlog.event_id:1 AND 
#   (process.name:(vssadmin.exe OR wbadmin.exe OR bcdedit.exe) OR
#    process.command_line:(*"delete shadows"* OR *shadowcopy* OR *recoveryenabled*))
#
# JSON DSL:
#   {
#     "query": {
#       "bool": {
#         "must": [
#           {"term": {"event.provider": "Microsoft-Windows-Sysmon"}},
#           {"term": {"winlog.event_id": 1}}
#         ],
#         "should": [
#           {"terms": {"process.name": ["vssadmin.exe", "wbadmin.exe", "bcdedit.exe"]}},
#           {"wildcard": {"process.command_line": "*delete shadows*"}},
#           {"wildcard": {"process.command_line": "*shadowcopy*"}},
#           {"wildcard": {"process.command_line": "*recoveryenabled*"}}
#         ],
#         "minimum_should_match": 1
#       }
#     }
#   }
# =============================================================================

class RR_2002_ShadowCopyDeletion(DetectionRule):
    """Detect shadow copy and backup deletion commands."""
    
    rule_id = "RR-2002"
    rule_name = "Shadow Copy / Backup Deletion Commands"
    mitre_techniques = ["T1490", "T1562", "T1059.001"]
    description = "Detects commands that delete shadow copies or disable recovery options"
    event_ids = [1]  # Sysmon ProcessCreate
    
    # Suspicious process names
    SUSPICIOUS_PROCESSES = {'vssadmin.exe', 'wbadmin.exe', 'bcdedit.exe', 'wmic.exe'}
    
    # Suspicious command line patterns
    SUSPICIOUS_PATTERNS = [
        r'delete\s+shadows',
        r'shadowcopy',
        r'recoveryenabled\s+no',
        r'bootstatuspolicy\s+ignoreallfailures',
        r'resize\s+shadowstorage',
        r'delete\s+catalog',
        r'delete\s+systemstatebackup',
    ]
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = self._extract_source(event)
        
        # Check event ID
        event_id = self._get_field(source, 'winlog.event_id')
        if event_id != 1:
            return None
        
        process_name = (self._get_field(source, 'process.name') or '').lower()
        command_line = (self._get_field(source, 'process.command_line') or '').lower()
        
        is_suspicious = False
        matched_indicator = None
        
        # Check process name
        if process_name in self.SUSPICIOUS_PROCESSES:
            # Additional check for specific commands
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, command_line, re.IGNORECASE):
                    is_suspicious = True
                    matched_indicator = pattern
                    break
            
            # vssadmin/wbadmin with delete is always suspicious
            if process_name in {'vssadmin.exe', 'wbadmin.exe'} and 'delete' in command_line:
                is_suspicious = True
                matched_indicator = f"{process_name} delete"
        
        # Check command line patterns even for other processes
        if not is_suspicious:
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, command_line, re.IGNORECASE):
                    is_suspicious = True
                    matched_indicator = pattern
                    break
        
        if not is_suspicious:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        process_entity_id = self._get_field(source, 'process.entity_id', '')
        
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(
            self.rule_id, host, process_entity_id, command_line[:100]
        )
        
        if context.is_duplicate(fingerprint):
            return None
        
        context.mark_seen(fingerprint)
        
        summary = f"Shadow copy/backup deletion detected: {process_name} on {host}"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=15,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, process_entity_id],
            extra_raw={'matched_indicator': matched_indicator}
        )


# =============================================================================
# RULE RR-2003: Office -> Script Engine -> Network
# =============================================================================
#
# Detection Logic:
#   1. Track Office process spawning script engines (Event ID 1)
#   2. Track network connections from script engines (Event ID 3)
#   3. Correlate within 5 minutes on same host
#
# KQL Example (Process Create):
#   event.provider:"Microsoft-Windows-Sysmon" AND winlog.event_id:1 AND
#   process.parent.name:(WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE OR POWERPNT.EXE) AND
#   process.name:(powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe OR mshta.exe)
#
# KQL Example (Network):
#   event.provider:"Microsoft-Windows-Sysmon" AND winlog.event_id:3 AND
#   process.name:(powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe OR mshta.exe)
# =============================================================================

class RR_2003_OfficeScriptNetwork(DetectionRule):
    """Detect Office application spawning script that makes network connection."""
    
    rule_id = "RR-2003"
    rule_name = "Office -> Script Engine -> Network Connection"
    mitre_techniques = ["T1059.001", "T1071", "T1566.001"]
    description = "Detects Office applications spawning script engines that make network connections"
    event_ids = [1, 3]  # ProcessCreate and NetworkConnect
    
    OFFICE_PROCESSES = {'winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe', 'msaccess.exe'}
    SCRIPT_ENGINES = {'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'msbuild.exe'}
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = self._extract_source(event)
        event_id = self._get_field(source, 'winlog.event_id')
        
        host = self._get_field(source, 'host.name', 'unknown')
        process_name = (self._get_field(source, 'process.name') or '').lower()
        process_entity_id = self._get_field(source, 'process.entity_id', '')
        parent_name = (self._get_field(source, 'process.parent.name') or '').lower()
        
        # Event ID 1: Process Create - check for Office -> Script
        if event_id == 1:
            if parent_name in self.OFFICE_PROCESSES and process_name in self.SCRIPT_ENGINES:
                # Store for correlation
                context.add_to_correlation(host, process_entity_id, {
                    'type': 'script_spawn',
                    'source': source,
                    'parent': parent_name,
                    'child': process_name
                })
            return None  # Don't alert yet, wait for network
        
        # Event ID 3: Network Connection - check if from tracked script
        if event_id == 3:
            if process_name not in self.SCRIPT_ENGINES:
                return None
            
            # Check correlation window
            correlated = context.get_correlated_events(host, process_entity_id)
            script_spawn = None
            for evt in correlated:
                if evt.get('type') == 'script_spawn':
                    script_spawn = evt
                    break
            
            if not script_spawn:
                return None
            
            # We have Office -> Script -> Network!
            fingerprint = self._generate_fingerprint(
                self.rule_id, host, process_entity_id
            )
            
            if context.is_duplicate(fingerprint):
                return None
            
            context.mark_seen(fingerprint)
            
            dest_ip = self._get_field(source, 'destination.ip', 'unknown')
            dest_port = self._get_field(source, 'destination.port', 'unknown')
            parent = script_spawn.get('parent', 'Office')
            
            summary = f"Office macro chain: {parent} -> {process_name} -> {dest_ip}:{dest_port} on {host}"
            
            return self._create_alert(
                source=source,
                severity="HIGH",
                severity_num=10,
                summary=summary,
                fingerprint_parts=[self.rule_id, host, process_entity_id],
                extra_raw={
                    'office_parent': parent,
                    'script_engine': process_name,
                    'network_dest': f"{dest_ip}:{dest_port}"
                }
            )
        
        return None


# =============================================================================
# RULE RR-2004: LSASS Access / Credential Dump
# =============================================================================
#
# KQL Example:
#   event.provider:"Microsoft-Windows-Sysmon" AND winlog.event_id:10 AND
#   winlog.event_data.TargetImage:*lsass.exe
#
# JSON DSL:
#   {
#     "query": {
#       "bool": {
#         "must": [
#           {"term": {"event.provider": "Microsoft-Windows-Sysmon"}},
#           {"term": {"winlog.event_id": 10}},
#           {"wildcard": {"winlog.event_data.TargetImage": "*lsass.exe"}}
#         ]
#       }
#     }
#   }
# =============================================================================

class RR_2004_LsassAccess(DetectionRule):
    """Detect process access to LSASS (credential dumping)."""
    
    rule_id = "RR-2004"
    rule_name = "LSASS Access / Credential Dump Attempt"
    mitre_techniques = ["T1003.001"]
    description = "Detects processes accessing LSASS memory, indicating potential credential dumping"
    event_ids = [10]  # Sysmon ProcessAccess
    
    # Legitimate processes that access LSASS
    WHITELIST = {
        'lsass.exe', 'csrss.exe', 'services.exe', 'svchost.exe',
        'wininit.exe', 'wmiprvse.exe', 'taskmgr.exe', 'procexp.exe',
        'procexp64.exe', 'mrt.exe', 'msmpeng.exe'
    }
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = self._extract_source(event)
        
        event_id = self._get_field(source, 'winlog.event_id')
        if event_id != 10:
            return None
        
        # Check if target is LSASS
        target_image = (self._get_field(source, 'winlog.event_data.TargetImage') or '').lower()
        if 'lsass.exe' not in target_image:
            return None
        
        # Get source process
        source_image = (self._get_field(source, 'winlog.event_data.SourceImage') or '').lower()
        source_process = source_image.split('\\')[-1] if source_image else 'unknown'
        
        # Whitelist check
        if source_process in self.WHITELIST:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        process_entity_id = self._get_field(source, 'process.entity_id', '')
        
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(
            self.rule_id, host, source_image, process_entity_id
        )
        
        if context.is_duplicate(fingerprint):
            return None
        
        context.mark_seen(fingerprint)
        
        granted_access = self._get_field(source, 'winlog.event_data.GrantedAccess', '')
        
        summary = f"LSASS access detected: {source_process} accessing lsass.exe on {host}"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=15,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, source_image],
            extra_raw={
                'source_image': source_image,
                'target_image': target_image,
                'granted_access': granted_access
            }
        )


# =============================================================================
# RR-1001: Suspicious PowerShell Execution
# =============================================================================

class RR_1001_SuspiciousPowerShell(DetectionRule):
    """
    Detect PowerShell execution - common attack vector.
    
    Sysmon Event ID 1 (Process Create) where process is powershell.exe
    """
    
    rule_id = "RR-1001"
    rule_name = "Suspicious PowerShell Execution"
    mitre_techniques = ["T1059.001"]
    description = "PowerShell execution detected - commonly used in attacks"
    event_ids = [1]  # Process Create
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        # Get process image
        image = self._get_field(source, 'winlog.event_data.Image', '').lower()
        process_name = image.split('\\')[-1] if image else ''
        
        # Check if PowerShell
        if 'powershell' not in process_name:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        command_line = self._get_field(source, 'winlog.event_data.CommandLine', '')
        process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
        parent_image = self._get_field(source, 'winlog.event_data.ParentImage', '')
        
        # Generate fingerprint to prevent duplicates
        fingerprint = self._generate_fingerprint(
            self.rule_id, host, process_id, command_line[:100]
        )
        
        if context.is_duplicate(fingerprint):
            return None
        
        context.mark_seen(fingerprint)
        
        # Determine severity based on command line content
        severity = "HIGH"
        severity_num = 10
        
        # Escalate to CRITICAL for encoded commands or suspicious patterns
        suspicious_patterns = ['-enc', '-encodedcommand', 'bypass', 'hidden', 'downloadstring', 
                              'invoke-expression', 'iex', 'webclient', 'net.webclient']
        cmd_lower = command_line.lower()
        if any(pattern in cmd_lower for pattern in suspicious_patterns):
            severity = "CRITICAL"
            severity_num = 15
        
        summary = f"PowerShell execution on {host} by {user}"
        if command_line:
            summary += f": {command_line[:80]}..."
        
        return self._create_alert(
            source=source,
            severity=severity,
            severity_num=severity_num,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, process_id],
            extra_raw={
                'image': image,
                'command_line': command_line,
                'parent_image': parent_image,
                'user': user
            }
        )


# =============================================================================
# RR-1002: Office Application Spawning Script Interpreter
# =============================================================================

class RR_1002_OfficeSpawningScript(DetectionRule):
    """
    Detect Office applications spawning script interpreters.
    
    This is a classic macro-based attack pattern.
    """
    
    rule_id = "RR-1002"
    rule_name = "Office Spawning Script Interpreter"
    mitre_techniques = ["T1204", "T1059"]
    description = "Office application spawned a script interpreter - possible macro attack"
    event_ids = [1]  # Process Create
    
    OFFICE_PROCESSES = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe']
    SCRIPT_INTERPRETERS = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        # Get parent and child process
        parent_image = self._get_field(source, 'winlog.event_data.ParentImage', '').lower()
        child_image = self._get_field(source, 'winlog.event_data.Image', '').lower()
        
        parent_name = parent_image.split('\\')[-1] if parent_image else ''
        child_name = child_image.split('\\')[-1] if child_image else ''
        
        # Check if Office spawning script
        if parent_name not in self.OFFICE_PROCESSES:
            return None
        if child_name not in self.SCRIPT_INTERPRETERS:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        command_line = self._get_field(source, 'winlog.event_data.CommandLine', '')
        process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
        
        # Generate fingerprint
        fingerprint = self._generate_fingerprint(
            self.rule_id, host, parent_name, child_name, process_id
        )
        
        if context.is_duplicate(fingerprint):
            return None
        
        context.mark_seen(fingerprint)
        
        summary = f"Office macro attack: {parent_name} spawned {child_name} on {host}"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=15,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, process_id],
            extra_raw={
                'parent_image': parent_image,
                'child_image': child_image,
                'command_line': command_line,
                'user': user
            }
        )


# =============================================================================
# RR-1003: Network Activity from Script Interpreter
# =============================================================================

class RR_1003_ScriptNetworkActivity(DetectionRule):
    """
    Detect network connections from script interpreters.
    
    Sysmon Event ID 3 (Network Connection) from PowerShell/cmd/wscript.
    """
    
    rule_id = "RR-1003"
    rule_name = "Network Activity from Script"
    mitre_techniques = ["T1041", "T1071"]
    description = "Script interpreter made network connection - possible C2 or exfiltration"
    event_ids = [3]  # Network Connection
    
    SCRIPT_PROCESSES = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        # Get process making connection
        image = self._get_field(source, 'winlog.event_data.Image', '').lower()
        process_name = image.split('\\')[-1] if image else ''
        
        if process_name not in self.SCRIPT_PROCESSES:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        dest_ip = self._get_field(source, 'winlog.event_data.DestinationIp', '')
        dest_port = self._get_field(source, 'winlog.event_data.DestinationPort', '')
        dest_hostname = self._get_field(source, 'winlog.event_data.DestinationHostname', '')
        process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
        
        # Generate fingerprint (allow same process to alert for different destinations)
        fingerprint = self._generate_fingerprint(
            self.rule_id, host, process_name, dest_ip, dest_port
        )
        
        if context.is_duplicate(fingerprint):
            return None
        
        context.mark_seen(fingerprint)
        
        destination = dest_hostname or dest_ip
        summary = f"{process_name} network connection to {destination}:{dest_port} on {host}"
        
        return self._create_alert(
            source=source,
            severity="HIGH",
            severity_num=10,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, dest_ip, dest_port],
            extra_raw={
                'image': image,
                'destination_ip': dest_ip,
                'destination_port': dest_port,
                'destination_hostname': dest_hostname,
                'user': user
            }
        )


# =============================================================================
# RR-3001: VSSAdmin Shadow Copy Deletion
# =============================================================================

class RR_3001_VSSAdminDeletion(DetectionRule):
    """
    Detect vssadmin.exe being used to delete shadow copies.
    This is a critical ransomware indicator.
    """
    
    rule_id = "RR-3001"
    rule_name = "Shadow Copy Deletion via VSSAdmin"
    mitre_techniques = ["T1490"]
    description = "VSSAdmin used to delete shadow copies - critical ransomware indicator"
    event_ids = [1]  # Process Create
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        image = self._get_field(source, 'winlog.event_data.Image', '').lower()
        command_line = self._get_field(source, 'winlog.event_data.CommandLine', '').lower()
        process_name = image.split('\\')[-1] if image else ''
        
        # Check for vssadmin with delete
        if 'vssadmin' not in process_name and 'vssadmin' not in command_line:
            return None
        
        if 'delete' not in command_line and 'shadows' not in command_line:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
        parent_image = self._get_field(source, 'winlog.event_data.ParentImage', '')
        
        fingerprint = self._generate_fingerprint(self.rule_id, host, process_id)
        
        if context.is_duplicate(fingerprint):
            return None
        context.mark_seen(fingerprint)
        
        summary = f"RANSOMWARE: Shadow copy deletion on {host} by {user}: {command_line[:100]}"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=20,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, process_id],
            extra_raw={
                'image': image,
                'command_line': command_line,
                'parent_image': parent_image,
                'user': user
            }
        )


# =============================================================================
# RR-3002: Registry Run Key Persistence
# =============================================================================

class RR_3002_RegistryPersistence(DetectionRule):
    """
    Detect registry modifications for persistence (Run keys).
    """
    
    rule_id = "RR-3002"
    rule_name = "Registry Run Key Persistence"
    mitre_techniques = ["T1547.001"]
    description = "Registry Run key modified for persistence"
    event_ids = [13]  # Registry value set
    
    PERSISTENCE_KEYS = [
        'currentversion\\run',
        'currentversion\\runonce',
        'currentversion\\runservices',
        'currentversion\\policies\\explorer\\run'
    ]
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        target_object = self._get_field(source, 'winlog.event_data.TargetObject', '').lower()
        
        # Check if it's a persistence key
        is_persistence = any(key in target_object for key in self.PERSISTENCE_KEYS)
        if not is_persistence:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        image = self._get_field(source, 'winlog.event_data.Image', '')
        details = self._get_field(source, 'winlog.event_data.Details', '')
        
        fingerprint = self._generate_fingerprint(self.rule_id, host, target_object)
        
        if context.is_duplicate(fingerprint):
            return None
        context.mark_seen(fingerprint)
        
        _key_name = target_object.split('\\')[-1]
        summary = f"PERSISTENCE: Registry Run key modified on {host}: {_key_name}"
        
        return self._create_alert(
            source=source,
            severity="HIGH",
            severity_num=12,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, target_object],
            extra_raw={
                'target_object': target_object,
                'details': details,
                'image': image,
                'user': user
            }
        )


# =============================================================================
# RR-3003: Ransomware File Extension
# =============================================================================

class RR_3003_RansomwareExtension(DetectionRule):
    """
    Detect file creation with known ransomware extensions.
    """
    
    rule_id = "RR-3003"
    rule_name = "Ransomware File Extension Detected"
    mitre_techniques = ["T1486"]
    description = "File created with known ransomware extension"
    event_ids = [11]  # File Create
    
    RANSOMWARE_EXTENSIONS = [
        '.locked', '.encrypted', '.crypted', '.enc', '.crypto',
        '.lockbit', '.lockbit3', '.conti', '.alphv', '.blackcat',
        '.revil', '.sodinokibi', '.ryuk', '.ryk', '.maze',
        '.wannacry', '.wcry', '.wncry', '.locky', '.cerber',
        '.dharma', '.phobos', '.stop', '.djvu', '.hive',
        '.blackbasta', '.royal', '.play', '.clop', '.cuba'
    ]
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        target_filename = self._get_field(source, 'winlog.event_data.TargetFilename', '').lower()
        
        # Check for ransomware extension
        matched_ext = None
        for ext in self.RANSOMWARE_EXTENSIONS:
            if target_filename.endswith(ext):
                matched_ext = ext
                break
        
        if not matched_ext:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        image = self._get_field(source, 'winlog.event_data.Image', '')
        process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
        
        fingerprint = self._generate_fingerprint(self.rule_id, host, target_filename)
        
        if context.is_duplicate(fingerprint):
            return None
        context.mark_seen(fingerprint)
        
        filename = target_filename.split('\\')[-1] if '\\' in target_filename else target_filename
        summary = f"RANSOMWARE: File encrypted on {host}: {filename} (extension: {matched_ext})"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=18,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, target_filename],
            extra_raw={
                'target_filename': target_filename,
                'extension': matched_ext,
                'image': image,
                'user': user
            }
        )


# =============================================================================
# RR-3004: Ransom Note Creation
# =============================================================================

class RR_3004_RansomNoteCreation(DetectionRule):
    """
    Detect creation of ransom note files.
    """
    
    rule_id = "RR-3004"
    rule_name = "Ransom Note File Created"
    mitre_techniques = ["T1486"]
    description = "Ransom note file created - active ransomware attack"
    event_ids = [11]  # File Create
    
    RANSOM_NOTE_PATTERNS = [
        'readme', 'read_me', 'read-me', 'how_to', 'how-to', 'howto',
        'decrypt', 'restore', 'recover', 'unlock', 'warning',
        'attention', 'important', 'help_decrypt', 'files_encrypted',
        'ransom', 'lockbit', 'conti', 'alphv', 'blackcat', 'revil',
        'ryuk', 'maze', 'final_warning', 'locked_screen'
    ]
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        target_filename = self._get_field(source, 'winlog.event_data.TargetFilename', '').lower()
        filename_only = target_filename.split('\\')[-1] if '\\' in target_filename else target_filename
        
        # Check for ransom note patterns
        is_ransom_note = any(pattern in filename_only for pattern in self.RANSOM_NOTE_PATTERNS)
        
        # Also check for common ransom note extensions with suspicious names
        if not is_ransom_note:
            if filename_only.endswith('.txt') or filename_only.endswith('.html') or filename_only.endswith('.hta'):
                # Check for all caps or exclamation marks (common in ransom notes)
                if '!!!' in filename_only or filename_only.upper() == filename_only:
                    is_ransom_note = True
        
        if not is_ransom_note:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        image = self._get_field(source, 'winlog.event_data.Image', '')
        
        fingerprint = self._generate_fingerprint(self.rule_id, host, target_filename)
        
        if context.is_duplicate(fingerprint):
            return None
        context.mark_seen(fingerprint)
        
        summary = f"RANSOMWARE: Ransom note created on {host}: {filename_only}"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=20,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, target_filename],
            extra_raw={
                'target_filename': target_filename,
                'image': image,
                'user': user
            }
        )


# =============================================================================
# RR-3005: WMIC Shadow Copy Deletion
# =============================================================================

class RR_3005_WMICShadowDelete(DetectionRule):
    """
    Detect WMIC being used to delete shadow copies.
    """
    
    rule_id = "RR-3005"
    rule_name = "Shadow Copy Deletion via WMIC"
    mitre_techniques = ["T1490"]
    description = "WMIC used to delete shadow copies - ransomware indicator"
    event_ids = [1]  # Process Create
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        image = self._get_field(source, 'winlog.event_data.Image', '').lower()
        command_line = self._get_field(source, 'winlog.event_data.CommandLine', '').lower()
        process_name = image.split('\\')[-1] if image else ''
        
        # Check for wmic shadowcopy delete
        if 'wmic' not in process_name and 'wmic' not in command_line:
            return None
        
        if 'shadowcopy' not in command_line or 'delete' not in command_line:
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
        
        fingerprint = self._generate_fingerprint(self.rule_id, host, process_id)
        
        if context.is_duplicate(fingerprint):
            return None
        context.mark_seen(fingerprint)
        
        summary = f"RANSOMWARE: WMIC shadow copy deletion on {host}: {command_line[:100]}"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=20,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, process_id],
            extra_raw={
                'image': image,
                'command_line': command_line,
                'user': user
            }
        )


# =============================================================================
# RR-3006: BCDEdit Boot Recovery Disable
# =============================================================================

class RR_3006_BCDEditRecoveryDisable(DetectionRule):
    """
    Detect BCDEdit being used to disable recovery options.
    """
    
    rule_id = "RR-3006"
    rule_name = "Boot Recovery Disabled via BCDEdit"
    mitre_techniques = ["T1490"]
    description = "BCDEdit used to disable boot recovery - ransomware indicator"
    event_ids = [1]  # Process Create
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        image = self._get_field(source, 'winlog.event_data.Image', '').lower()
        command_line = self._get_field(source, 'winlog.event_data.CommandLine', '').lower()
        process_name = image.split('\\')[-1] if image else ''
        
        if 'bcdedit' not in process_name and 'bcdedit' not in command_line:
            return None
        
        # Check for recovery disable patterns
        disable_patterns = ['recoveryenabled no', 'bootstatuspolicy ignoreallfailures', 'safeboot']
        if not any(pattern in command_line for pattern in disable_patterns):
            return None
        
        host = self._get_field(source, 'host.name', 'unknown')
        user = self._get_field(source, 'winlog.event_data.User', 'unknown')
        process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
        
        fingerprint = self._generate_fingerprint(self.rule_id, host, process_id)
        
        if context.is_duplicate(fingerprint):
            return None
        context.mark_seen(fingerprint)
        
        summary = f"RANSOMWARE: Boot recovery disabled on {host}: {command_line[:100]}"
        
        return self._create_alert(
            source=source,
            severity="CRITICAL",
            severity_num=18,
            summary=summary,
            fingerprint_parts=[self.rule_id, host, process_id],
            extra_raw={
                'image': image,
                'command_line': command_line,
                'user': user
            }
        )


# =============================================================================
# RR-3007: Suspicious File Rename (Mass)
# =============================================================================

class RR_3007_SuspiciousRename(DetectionRule):
    """
    Detect suspicious file operations that indicate ransomware.
    Looks for python.exe or other processes creating files with ransomware patterns.
    """
    
    rule_id = "RR-3007"
    rule_name = "Suspicious Mass File Operation"
    mitre_techniques = ["T1486"]
    description = "Suspicious file operation detected - possible ransomware"
    event_ids = [11]  # File Create
    
    def evaluate(self, event: Dict, context: DetectionContext) -> Optional[DetectionAlert]:
        source = event.get('_source', {})
        
        target_filename = self._get_field(source, 'winlog.event_data.TargetFilename', '').lower()
        image = self._get_field(source, 'winlog.event_data.Image', '').lower()
        
        # Look for python.exe creating suspicious files (our agent)
        if 'python' in image:
            # Check for ransomware-like extensions
            suspicious_exts = ['.locked', '.encrypted', '.crypted', '.lockbit', '.conti', 
                             '.alphv', '.revil', '.ryuk', '.maze', '.ryk']
            
            is_suspicious = any(target_filename.endswith(ext) for ext in suspicious_exts)
            
            if not is_suspicious:
                return None
            
            host = self._get_field(source, 'host.name', 'unknown')
            process_id = self._get_field(source, 'winlog.event_data.ProcessId', '')
            
            fingerprint = self._generate_fingerprint(self.rule_id, host, target_filename)
            
            if context.is_duplicate(fingerprint):
                return None
            context.mark_seen(fingerprint)
            
            filename = target_filename.split('\\')[-1]
            summary = f"RANSOMWARE SIMULATION: File encrypted on {host}: {filename}"
            
            return self._create_alert(
                source=source,
                severity="HIGH",
                severity_num=15,
                summary=summary,
                fingerprint_parts=[self.rule_id, host, target_filename],
                extra_raw={
                    'target_filename': target_filename,
                    'image': image
                }
            )
        
        return None


# =============================================================================
# Rule Registry
# =============================================================================

DETECTION_RULES: List[DetectionRule] = [
    # PowerShell and script-based attacks
    RR_1001_SuspiciousPowerShell(),
    RR_1002_OfficeSpawningScript(),
    RR_1003_ScriptNetworkActivity(),
    # Existing ransomware-specific rules
    RR_2001_MassFileCreate(),
    RR_2002_ShadowCopyDeletion(),
    RR_2003_OfficeScriptNetwork(),
    RR_2004_LsassAccess(),
    # NEW: Ransomware behavior detection
    RR_3001_VSSAdminDeletion(),
    RR_3002_RegistryPersistence(),
    RR_3003_RansomwareExtension(),
    RR_3004_RansomNoteCreation(),
    RR_3005_WMICShadowDelete(),
    RR_3006_BCDEditRecoveryDisable(),
    RR_3007_SuspiciousRename(),
]

def get_rules_for_event_id(event_id: int) -> List[DetectionRule]:
    """Get rules that process a specific Sysmon event ID."""
    return [rule for rule in DETECTION_RULES if event_id in rule.event_ids]

def get_all_event_ids() -> List[int]:
    """Get all Sysmon event IDs processed by rules."""
    ids = set()
    for rule in DETECTION_RULES:
        ids.update(rule.event_ids)
    return sorted(list(ids))
