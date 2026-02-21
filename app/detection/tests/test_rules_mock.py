"""Unit tests for ransomware detection rules using mocked ES data.

Run with: pytest app/detection/tests/test_rules_mock.py -v
"""

import pytest
from datetime import datetime, timedelta

from ..ransomware_rules import (
    DetectionContext,
    RR_2001_MassFileCreate,
    RR_2002_ShadowCopyDeletion,
    RR_2003_OfficeScriptNetwork,
    RR_2004_LsassAccess,
    DETECTION_RULES
)


# =============================================================================
# Mock Event Fixtures
# =============================================================================

def make_sysmon_event(
    event_id: int,
    host: str = "WORKSTATION-01",
    process_name: str = "test.exe",
    command_line: str = "",
    parent_name: str = "explorer.exe",
    entity_id: str = "test-entity-123",
    timestamp: str = None,
    **extra
) -> dict:
    """Create a mock Sysmon event in Elasticsearch format."""
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + 'Z'
    
    source = {
        '@timestamp': timestamp,
        'host': {'name': host},
        'user': {'name': 'testuser'},
        'process': {
            'name': process_name,
            'entity_id': entity_id,
            'command_line': command_line,
            'pid': 1234,
            'parent': {
                'name': parent_name,
                'command_line': ''
            }
        },
        'winlog': {
            'event_id': event_id,
            'provider_name': 'Microsoft-Windows-Sysmon'
        },
        'event': {
            'provider': 'Microsoft-Windows-Sysmon',
            'action': 'Process Create' if event_id == 1 else 'Unknown'
        }
    }
    
    # Add extra fields
    source.update(extra)
    
    return {
        '_index': 'winlogbeat-2024.01.01',
        '_id': f'mock-{entity_id}-{event_id}',
        '_source': source
    }


def make_file_create_event(host: str, process_name: str, file_path: str, entity_id: str = None):
    """Create Sysmon Event ID 11 (FileCreate)."""
    return make_sysmon_event(
        event_id=11,
        host=host,
        process_name=process_name,
        entity_id=entity_id or f"entity-{process_name}",
        file={'path': file_path, 'name': file_path.split('\\')[-1]}
    )


def make_process_create_event(host: str, process_name: str, command_line: str, parent_name: str = "explorer.exe"):
    """Create Sysmon Event ID 1 (ProcessCreate)."""
    return make_sysmon_event(
        event_id=1,
        host=host,
        process_name=process_name,
        command_line=command_line,
        parent_name=parent_name
    )


def make_network_event(host: str, process_name: str, dest_ip: str, dest_port: int, entity_id: str):
    """Create Sysmon Event ID 3 (NetworkConnect)."""
    event = make_sysmon_event(
        event_id=3,
        host=host,
        process_name=process_name,
        entity_id=entity_id
    )
    event['_source']['destination'] = {'ip': dest_ip, 'port': dest_port}
    return event


def make_process_access_event(host: str, source_image: str, target_image: str):
    """Create Sysmon Event ID 10 (ProcessAccess)."""
    event = make_sysmon_event(
        event_id=10,
        host=host,
        process_name=source_image.split('\\')[-1]
    )
    event['_source']['winlog']['event_data'] = {
        'SourceImage': source_image,
        'TargetImage': target_image,
        'GrantedAccess': '0x1410'
    }
    return event


# =============================================================================
# Test RR-2001: Mass File Create
# =============================================================================

class TestRR2001MassFileCreate:
    """Tests for mass file creation detection."""
    
    def test_no_trigger_below_threshold(self):
        """Should not trigger with few file events."""
        rule = RR_2001_MassFileCreate()
        context = DetectionContext()
        
        # Create 10 file events (below threshold of 50)
        for i in range(10):
            event = make_file_create_event(
                host="WORKSTATION-01",
                process_name="notepad.exe",
                file_path=f"C:\\temp\\file{i}.txt",
                entity_id="entity-notepad"
            )
            result = rule.evaluate(event, context)
        
        # Should not trigger
        assert result is None
    
    def test_trigger_at_high_threshold(self):
        """Should trigger HIGH severity at 50+ file events."""
        rule = RR_2001_MassFileCreate()
        context = DetectionContext()
        
        # Create 55 file events
        result = None
        for i in range(55):
            event = make_file_create_event(
                host="WORKSTATION-01",
                process_name="ransomware.exe",
                file_path=f"C:\\Users\\victim\\Documents\\file{i}.docx.locked",
                entity_id="entity-ransomware"
            )
            result = rule.evaluate(event, context)
        
        # Should trigger
        assert result is not None
        assert result.rule_id == "RR-2001"
        assert result.severity in ("HIGH", "CRITICAL")
        assert result.severity_num >= 10
        assert "T1486" in result.mitre
    
    def test_deduplication(self):
        """Should not create duplicate alerts for same process."""
        rule = RR_2001_MassFileCreate()
        context = DetectionContext()
        
        alerts = []
        for i in range(100):
            event = make_file_create_event(
                host="WORKSTATION-01",
                process_name="ransomware.exe",
                file_path=f"C:\\temp\\file{i}.txt",
                entity_id="entity-ransomware"
            )
            result = rule.evaluate(event, context)
            if result:
                alerts.append(result)
        
        # Should only have 1 alert (deduplicated)
        assert len(alerts) == 1


# =============================================================================
# Test RR-2002: Shadow Copy Deletion
# =============================================================================

class TestRR2002ShadowCopyDeletion:
    """Tests for shadow copy deletion detection."""
    
    def test_vssadmin_delete_shadows(self):
        """Should detect vssadmin delete shadows command."""
        rule = RR_2002_ShadowCopyDeletion()
        context = DetectionContext()
        
        event = make_process_create_event(
            host="WORKSTATION-01",
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet"
        )
        
        result = rule.evaluate(event, context)
        
        assert result is not None
        assert result.rule_id == "RR-2002"
        assert result.severity == "CRITICAL"
        assert result.severity_num == 15
        assert "T1490" in result.mitre
    
    def test_bcdedit_recovery_disabled(self):
        """Should detect bcdedit disabling recovery."""
        rule = RR_2002_ShadowCopyDeletion()
        context = DetectionContext()
        
        event = make_process_create_event(
            host="WORKSTATION-01",
            process_name="bcdedit.exe",
            command_line="bcdedit /set {default} recoveryenabled no"
        )
        
        result = rule.evaluate(event, context)
        
        assert result is not None
        assert result.rule_id == "RR-2002"
        assert result.severity == "CRITICAL"
    
    def test_wbadmin_delete_catalog(self):
        """Should detect wbadmin delete catalog."""
        rule = RR_2002_ShadowCopyDeletion()
        context = DetectionContext()
        
        event = make_process_create_event(
            host="WORKSTATION-01",
            process_name="wbadmin.exe",
            command_line="wbadmin delete catalog -quiet"
        )
        
        result = rule.evaluate(event, context)
        
        assert result is not None
        assert result.rule_id == "RR-2002"
    
    def test_no_trigger_normal_vssadmin(self):
        """Should not trigger for normal vssadmin usage."""
        rule = RR_2002_ShadowCopyDeletion()
        context = DetectionContext()
        
        event = make_process_create_event(
            host="WORKSTATION-01",
            process_name="vssadmin.exe",
            command_line="vssadmin list shadows"
        )
        
        result = rule.evaluate(event, context)
        
        assert result is None


# =============================================================================
# Test RR-2003: Office -> Script -> Network
# =============================================================================

class TestRR2003OfficeScriptNetwork:
    """Tests for Office macro chain detection."""
    
    def test_office_to_powershell_to_network(self):
        """Should detect Office spawning PowerShell that makes network connection."""
        rule = RR_2003_OfficeScriptNetwork()
        context = DetectionContext()
        
        # Step 1: Office spawns PowerShell
        spawn_event = make_sysmon_event(
            event_id=1,
            host="WORKSTATION-01",
            process_name="powershell.exe",
            parent_name="WINWORD.EXE",
            entity_id="ps-entity-123"
        )
        result1 = rule.evaluate(spawn_event, context)
        assert result1 is None  # Should not alert yet
        
        # Step 2: PowerShell makes network connection
        network_event = make_network_event(
            host="WORKSTATION-01",
            process_name="powershell.exe",
            dest_ip="192.168.1.100",
            dest_port=443,
            entity_id="ps-entity-123"
        )
        result2 = rule.evaluate(network_event, context)
        
        # Should trigger now
        assert result2 is not None
        assert result2.rule_id == "RR-2003"
        assert result2.severity == "HIGH"
        assert "T1059.001" in result2.mitre
    
    def test_no_trigger_without_office_parent(self):
        """Should not trigger if script not spawned by Office."""
        rule = RR_2003_OfficeScriptNetwork()
        context = DetectionContext()
        
        # PowerShell spawned by explorer (not Office)
        spawn_event = make_sysmon_event(
            event_id=1,
            host="WORKSTATION-01",
            process_name="powershell.exe",
            parent_name="explorer.exe",
            entity_id="ps-entity-456"
        )
        rule.evaluate(spawn_event, context)
        
        # Network connection
        network_event = make_network_event(
            host="WORKSTATION-01",
            process_name="powershell.exe",
            dest_ip="192.168.1.100",
            dest_port=443,
            entity_id="ps-entity-456"
        )
        result = rule.evaluate(network_event, context)
        
        # Should not trigger
        assert result is None


# =============================================================================
# Test RR-2004: LSASS Access
# =============================================================================

class TestRR2004LsassAccess:
    """Tests for LSASS access detection."""
    
    def test_mimikatz_lsass_access(self):
        """Should detect suspicious process accessing LSASS."""
        rule = RR_2004_LsassAccess()
        context = DetectionContext()
        
        event = make_process_access_event(
            host="WORKSTATION-01",
            source_image="C:\\temp\\mimikatz.exe",
            target_image="C:\\Windows\\System32\\lsass.exe"
        )
        
        result = rule.evaluate(event, context)
        
        assert result is not None
        assert result.rule_id == "RR-2004"
        assert result.severity == "CRITICAL"
        assert result.severity_num == 15
        assert "T1003.001" in result.mitre
    
    def test_whitelist_taskmgr(self):
        """Should not trigger for whitelisted processes like taskmgr."""
        rule = RR_2004_LsassAccess()
        context = DetectionContext()
        
        event = make_process_access_event(
            host="WORKSTATION-01",
            source_image="C:\\Windows\\System32\\taskmgr.exe",
            target_image="C:\\Windows\\System32\\lsass.exe"
        )
        
        result = rule.evaluate(event, context)
        
        assert result is None
    
    def test_no_trigger_non_lsass_target(self):
        """Should not trigger for non-LSASS targets."""
        rule = RR_2004_LsassAccess()
        context = DetectionContext()
        
        event = make_process_access_event(
            host="WORKSTATION-01",
            source_image="C:\\temp\\test.exe",
            target_image="C:\\Windows\\System32\\svchost.exe"
        )
        
        result = rule.evaluate(event, context)
        
        assert result is None


# =============================================================================
# Test Rule Registry
# =============================================================================

class TestRuleRegistry:
    """Tests for rule registry."""
    
    def test_all_rules_registered(self):
        """All rules should be in DETECTION_RULES."""
        assert len(DETECTION_RULES) == 4
        
        rule_ids = [r.rule_id for r in DETECTION_RULES]
        assert "RR-2001" in rule_ids
        assert "RR-2002" in rule_ids
        assert "RR-2003" in rule_ids
        assert "RR-2004" in rule_ids
    
    def test_all_rules_have_mitre(self):
        """All rules should have MITRE techniques."""
        for rule in DETECTION_RULES:
            assert len(rule.mitre_techniques) > 0
            assert all(t.startswith('T') for t in rule.mitre_techniques)
