"""Detection Engine for RansomRun platform.

This module provides Sysmon-based ransomware behavior detection rules
that process events from Elasticsearch and generate alerts.
"""

from .ransomware_rules import (
    DETECTION_RULES,
    RR_2001_MassFileCreate,
    RR_2002_ShadowCopyDeletion,
    RR_2003_OfficeScriptNetwork,
    RR_2004_LsassAccess,
)
from .engine import DetectionEngine

__all__ = [
    'DETECTION_RULES',
    'DetectionEngine',
    'RR_2001_MassFileCreate',
    'RR_2002_ShadowCopyDeletion',
    'RR_2003_OfficeScriptNetwork',
    'RR_2004_LsassAccess',
]
