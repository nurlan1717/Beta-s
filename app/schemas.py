"""Pydantic schemas for RANSOMRUN API."""

from datetime import datetime
from typing import Optional, Any, List
from pydantic import BaseModel


# ============ Agent Schemas ============

class AgentRegisterRequest(BaseModel):
    agent_id: str
    hostname: str
    ip_address: Optional[str] = None


class AgentRegisterResponse(BaseModel):
    id: int
    name: str
    agent_id: str
    ip_address: Optional[str]
    status: str

    class Config:
        from_attributes = True


class TaskResponse(BaseModel):
    task_id: Optional[int]
    type: Optional[str] = None
    parameters: Optional[dict] = None


class TaskResultRequest(BaseModel):
    task_id: int
    status: str  # "completed" or "failed"
    result_message: Optional[str] = None


class TaskResultResponse(BaseModel):
    success: bool
    message: str


# ============ Wazuh Alert Schemas ============

class WazuhAlertRule(BaseModel):
    id: str
    description: Optional[str] = None
    level: Optional[int] = None


class WazuhAlertAgent(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None


class WazuhAlertRequest(BaseModel):
    rule: WazuhAlertRule
    agent: Optional[WazuhAlertAgent] = None
    data: Optional[dict] = None
    timestamp: Optional[str] = None


class AlertResponse(BaseModel):
    success: bool
    alert_id: int
    tasks_created: int


# ============ Simulation Schemas ============

class RunSimulationRequest(BaseModel):
    host_id: int
    scenario_id: int


class RunSimulationResponse(BaseModel):
    success: bool
    run_id: int
    message: str


# ============ Host Schemas ============

class HostSchema(BaseModel):
    id: int
    name: str
    agent_id: str
    ip_address: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============ Scenario Schemas ============

class RansomNoteConfig(BaseModel):
    """Configuration for ransom note creation."""
    filename: str = "README_RESTORE.txt"
    content: str = "Your files have been encrypted... (SIMULATION ONLY)"
    locations: List[str] = ["target_root"]


class PersistenceConfig(BaseModel):
    """Configuration for persistence simulation."""
    enabled: bool = False
    type: str = "registry_run_key"  # registry_run_key, scheduled_task


class ExfiltrationConfig(BaseModel):
    """Configuration for exfiltration simulation."""
    enabled: bool = False
    method: str = "zip_only"  # Only zip_only allowed for safety
    target_dir: str = "C:\\RansomLab\\ExfilSim"


class ScenarioConfigSchema(BaseModel):
    """
    Full scenario configuration schema.
    
    IMPORTANT: All behaviors are SIMULATION ONLY.
    No real encryption, no network exfiltration, no destructive actions.
    """
    target_dirs: List[str] = ["C:\\RansomLab"]
    file_extensions: List[str] = [".docx", ".xlsx", ".pdf", ".txt"]
    max_files: int = 150
    rename_extension: str = ".locked"
    ransom_note: Optional[RansomNoteConfig] = None
    simulate_vssadmin: bool = False
    simulate_persistence: Optional[PersistenceConfig] = None
    simulate_exfiltration: Optional[ExfiltrationConfig] = None
    intensity_level: int = 3  # 1-5 scale
    delay_seconds_between_steps: int = 0
    behavior_style: str = "LOUD_CRYPTO"  # LOUD_CRYPTO, STEALTHY, LOCKER_LIKE
    tags: List[str] = []
    quarantine_mode: bool = False  # For wiper simulation


class ScenarioSchema(BaseModel):
    id: int
    key: str
    name: str
    description: Optional[str]
    category: Optional[str] = None
    config: Optional[dict] = None
    is_custom: bool = False
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScenarioCreateRequest(BaseModel):
    """Request schema for creating a new custom scenario."""
    name: str
    description: Optional[str] = None
    category: str = "crypto"
    behavior_style: str = "LOUD_CRYPTO"
    intensity_level: int = 3
    target_dirs: List[str] = ["C:\\RansomLab"]
    file_extensions: List[str] = [".docx", ".xlsx", ".pdf", ".txt"]
    max_files: int = 150
    rename_extension: str = ".locked"
    ransom_note_filename: str = "README_RESTORE.txt"
    ransom_note_content: str = "Your files have been encrypted... (SIMULATION ONLY)"
    ransom_note_locations: List[str] = ["target_root"]
    simulate_vssadmin: bool = False
    simulate_persistence: bool = False
    persistence_type: str = "registry_run_key"
    simulate_exfiltration: bool = False
    exfil_target_dir: str = "C:\\RansomLab\\ExfilSim"
    delay_seconds: int = 0
    tags: List[str] = []
    created_by: Optional[str] = "admin"


class ScenarioUpdateRequest(BaseModel):
    """Request schema for updating an existing custom scenario."""
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    behavior_style: Optional[str] = None
    intensity_level: Optional[int] = None
    target_dirs: Optional[List[str]] = None
    file_extensions: Optional[List[str]] = None
    max_files: Optional[int] = None
    rename_extension: Optional[str] = None
    ransom_note_filename: Optional[str] = None
    ransom_note_content: Optional[str] = None
    ransom_note_locations: Optional[List[str]] = None
    simulate_vssadmin: Optional[bool] = None
    simulate_persistence: Optional[bool] = None
    persistence_type: Optional[str] = None
    simulate_exfiltration: Optional[bool] = None
    exfil_target_dir: Optional[str] = None
    delay_seconds: Optional[int] = None
    tags: Optional[List[str]] = None


class ScenarioExportSchema(BaseModel):
    """Schema for exporting/importing scenarios."""
    name: str
    key: str
    description: Optional[str] = None
    category: str
    config: dict
    tags: List[str] = []


class ScenarioImportRequest(BaseModel):
    """Request schema for importing a scenario."""
    name: str
    description: Optional[str] = None
    category: str = "crypto"
    config: dict
    tags: List[str] = []


class ScenarioValidationError(BaseModel):
    """Validation error response."""
    field: str
    message: str


class ScenarioResponse(BaseModel):
    """Response for scenario operations."""
    success: bool
    scenario_id: Optional[int] = None
    message: str
    errors: List[ScenarioValidationError] = []


# ============ Run Schemas ============

class RunSchema(BaseModel):
    id: int
    host_id: int
    scenario_id: int
    status: str
    started_at: Optional[datetime]
    ended_at: Optional[datetime]
    notes: Optional[str]

    class Config:
        from_attributes = True


# ============ Task Schemas ============

class TaskSchema(BaseModel):
    id: int
    run_id: Optional[int]
    host_id: int
    type: str
    parameters: Optional[dict]
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    result_message: Optional[str]

    class Config:
        from_attributes = True


# ============ Alert Schemas ============

class AlertSchema(BaseModel):
    id: int
    host_id: Optional[int]
    run_id: Optional[int]
    rule_id: str
    rule_description: Optional[str]
    agent_name: Optional[str]
    severity: int
    timestamp: datetime
    raw: Optional[Any]

    class Config:
        from_attributes = True


# ============ Playbook Schemas ============

class PlaybookSchema(BaseModel):
    id: int
    name: str
    rule_id: str
    actions: list
    enabled: bool

    class Config:
        from_attributes = True


# ============ RunEvent Schemas ============

class RunEventSchema(BaseModel):
    id: int
    run_id: int
    host_id: Optional[int]
    event_type: str
    timestamp: datetime
    details: Optional[dict]

    class Config:
        from_attributes = True


class RunEventCreate(BaseModel):
    run_id: int
    host_id: Optional[int] = None
    event_type: str
    details: Optional[dict] = None


# ============ AffectedFile Schemas ============

class AffectedFileSchema(BaseModel):
    id: int
    run_id: int
    host_id: Optional[int]
    original_path: str
    new_path: Optional[str]
    action_type: str
    timestamp: datetime

    class Config:
        from_attributes = True


class AffectedFileCreate(BaseModel):
    run_id: int
    host_id: Optional[int] = None
    original_path: str
    new_path: Optional[str] = None
    action_type: str


# ============ Metric Schemas ============

class MetricSchema(BaseModel):
    id: int
    run_id: int
    host_id: Optional[int]
    name: str
    value: float
    created_at: datetime

    class Config:
        from_attributes = True


class MetricCreate(BaseModel):
    run_id: int
    host_id: Optional[int] = None
    name: str
    value: float


# ============ IOC Schemas ============

class IOCSchema(BaseModel):
    id: int
    run_id: int
    host_id: Optional[int]
    ioc_type: str
    value: str
    context: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True


class IOCCreate(BaseModel):
    run_id: int
    host_id: Optional[int] = None
    ioc_type: str
    value: str
    context: Optional[str] = None


# ============ ELK Config Schemas ============

class ELKConfigSchema(BaseModel):
    id: int
    url: str
    username: Optional[str]
    index_alerts: str
    index_logs: str
    enabled: bool
    last_sync: Optional[datetime]

    class Config:
        from_attributes = True


class ELKConfigCreate(BaseModel):
    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    index_alerts: str = '.alerts-security.alerts-*'
    index_logs: str = 'logs-*'
    enabled: bool = True


class ELKConfigUpdate(BaseModel):
    url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    index_alerts: Optional[str] = None
    index_logs: Optional[str] = None
    enabled: Optional[bool] = None


# ============ ELK Alert Schemas ============

class ELKAlertMITRE(BaseModel):
    technique: str
    technique_name: str
    tactic: str
    tactic_id: str


class ELKAlertSchema(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    rule_description: Optional[str]
    agent_name: str
    host_ip: Optional[str]
    severity: int
    severity_label: str
    timestamp: str
    mitre: ELKAlertMITRE
    raw: Optional[dict] = None


# ============ Agent Extended Schemas ============

class AgentSimulationResult(BaseModel):
    """Extended result from agent including forensic data."""
    task_id: int
    status: str
    result_message: Optional[str] = None
    files_affected: Optional[List[dict]] = None
    iocs: Optional[List[dict]] = None
    metrics: Optional[dict] = None
    events: Optional[List[dict]] = None


# ============ SIEM Schemas ============

class AlertFilterRequest(BaseModel):
    host_id: Optional[int] = None
    rule_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    min_severity: Optional[int] = None
    limit: int = 100
    offset: int = 0


class AlertStatsResponse(BaseModel):
    total_alerts: int
    alerts_by_rule: dict
    alerts_by_severity: dict
    alerts_over_time: List[dict]
