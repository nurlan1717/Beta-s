"""
Scenarios API router for RANSOMRUN.

Provides CRUD operations for custom ransomware scenarios.
All scenarios are SIMULATION ONLY - no real encryption or malware.
"""

import re
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Scenario, ScenarioCategory
from ..schemas import (
    ScenarioSchema, ScenarioCreateRequest, ScenarioUpdateRequest,
    ScenarioExportSchema, ScenarioImportRequest, ScenarioResponse,
    ScenarioValidationError
)
from .. import crud

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


# =============================================================================
# SAFETY VALIDATION
# =============================================================================

# Directories that are NOT allowed to be targeted (safety measure)
FORBIDDEN_DIRECTORIES = [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\Users\\Default",
    "C:\\$Recycle.Bin",
    "C:\\System Volume Information",
]

# Maximum allowed files
MAX_FILES_LIMIT = 1000

# Allowed exfiltration methods (no network)
ALLOWED_EXFIL_METHODS = ["zip_only", "local_staging"]

# Allowed behavior styles
ALLOWED_BEHAVIOR_STYLES = ["LOUD_CRYPTO", "STEALTHY", "LOCKER_LIKE"]

# Allowed persistence types
ALLOWED_PERSISTENCE_TYPES = ["registry_run_key", "scheduled_task", "none"]


def normalize_path(path: str) -> str:
    """Normalize a Windows path for comparison."""
    # Replace double backslashes with single, then normalize
    normalized = path.replace("\\\\", "\\").replace("/", "\\")
    return normalized.upper().rstrip("\\")


def validate_scenario_config(request: ScenarioCreateRequest) -> List[ScenarioValidationError]:
    """
    Validate scenario configuration for safety and correctness.
    Returns list of validation errors (empty if valid).
    """
    errors = []
    
    # Validate target directories
    if not request.target_dirs:
        errors.append(ScenarioValidationError(
            field="target_dirs",
            message="At least one target directory is required"
        ))
    else:
        for dir_path in request.target_dirs:
            dir_normalized = normalize_path(dir_path)
            for forbidden in FORBIDDEN_DIRECTORIES:
                forbidden_normalized = normalize_path(forbidden)
                if dir_normalized == forbidden_normalized or dir_normalized.startswith(forbidden_normalized + "\\"):
                    errors.append(ScenarioValidationError(
                        field="target_dirs",
                        message=f"Directory '{dir_path}' is not allowed for safety reasons"
                    ))
                    break
    
    # Validate file extensions
    if request.file_extensions:
        for ext in request.file_extensions:
            if not ext.startswith("."):
                errors.append(ScenarioValidationError(
                    field="file_extensions",
                    message=f"Extension '{ext}' must start with a dot (e.g., '.docx')"
                ))
    
    # Validate max_files
    if request.max_files > MAX_FILES_LIMIT:
        errors.append(ScenarioValidationError(
            field="max_files",
            message=f"max_files cannot exceed {MAX_FILES_LIMIT}"
        ))
    if request.max_files < 1:
        errors.append(ScenarioValidationError(
            field="max_files",
            message="max_files must be at least 1"
        ))
    
    # Validate intensity level
    if request.intensity_level < 1 or request.intensity_level > 5:
        errors.append(ScenarioValidationError(
            field="intensity_level",
            message="intensity_level must be between 1 and 5"
        ))
    
    # Validate behavior style
    if request.behavior_style not in ALLOWED_BEHAVIOR_STYLES:
        errors.append(ScenarioValidationError(
            field="behavior_style",
            message=f"behavior_style must be one of: {', '.join(ALLOWED_BEHAVIOR_STYLES)}"
        ))
    
    # Validate ransom note filename (simple safe filename)
    if request.ransom_note_filename:
        if not re.match(r'^[\w\-. ]+$', request.ransom_note_filename):
            errors.append(ScenarioValidationError(
                field="ransom_note_filename",
                message="Ransom note filename contains invalid characters"
            ))
    
    # Validate persistence type
    if request.simulate_persistence and request.persistence_type not in ALLOWED_PERSISTENCE_TYPES:
        errors.append(ScenarioValidationError(
            field="persistence_type",
            message=f"persistence_type must be one of: {', '.join(ALLOWED_PERSISTENCE_TYPES)}"
        ))
    
    # Validate exfiltration (only local methods allowed)
    if request.simulate_exfiltration:
        # Exfil target dir must not be in forbidden directories
        exfil_normalized = normalize_path(request.exfil_target_dir)
        for forbidden in FORBIDDEN_DIRECTORIES:
            forbidden_normalized = normalize_path(forbidden)
            if exfil_normalized == forbidden_normalized or exfil_normalized.startswith(forbidden_normalized + "\\"):
                errors.append(ScenarioValidationError(
                    field="exfil_target_dir",
                    message=f"Exfil directory '{request.exfil_target_dir}' is not allowed"
                ))
                break
    
    # Validate delay
    if request.delay_seconds < 0:
        errors.append(ScenarioValidationError(
            field="delay_seconds",
            message="delay_seconds cannot be negative"
        ))
    if request.delay_seconds > 300:
        errors.append(ScenarioValidationError(
            field="delay_seconds",
            message="delay_seconds cannot exceed 300 seconds"
        ))
    
    return errors


def build_config_from_request(request: ScenarioCreateRequest) -> dict:
    """Build the scenario config JSON from a create request."""
    config = {
        "directories_to_target": request.target_dirs,
        "file_extensions": request.file_extensions,
        "max_files": request.max_files,
        "rename_pattern": request.rename_extension,
        "ransom_note": {
            "filename": request.ransom_note_filename,
            "content": request.ransom_note_content,
            "locations": request.ransom_note_locations
        },
        "simulate_vssadmin": request.simulate_vssadmin,
        "simulate_persistence": request.simulate_persistence,
        "persistence_type": request.persistence_type if request.simulate_persistence else None,
        "simulate_exfiltration": request.simulate_exfiltration,
        "exfil_target_dir": request.exfil_target_dir if request.simulate_exfiltration else None,
        "intensity_level": request.intensity_level,
        "optional_delay_seconds": request.delay_seconds,
        "behavior_style": request.behavior_style,
        "tags": request.tags,
        "simulate_network_beacon": False,  # Always false for safety
        "quarantine_mode": False
    }
    return config


def update_config_from_request(existing_config: dict, request: ScenarioUpdateRequest) -> dict:
    """Update existing config with values from update request."""
    config = existing_config.copy() if existing_config else {}
    
    if request.target_dirs is not None:
        config["directories_to_target"] = request.target_dirs
    if request.file_extensions is not None:
        config["file_extensions"] = request.file_extensions
    if request.max_files is not None:
        config["max_files"] = request.max_files
    if request.rename_extension is not None:
        config["rename_pattern"] = request.rename_extension
    
    # Update ransom note
    if any([request.ransom_note_filename, request.ransom_note_content, request.ransom_note_locations]):
        if "ransom_note" not in config:
            config["ransom_note"] = {}
        if request.ransom_note_filename is not None:
            config["ransom_note"]["filename"] = request.ransom_note_filename
        if request.ransom_note_content is not None:
            config["ransom_note"]["content"] = request.ransom_note_content
        if request.ransom_note_locations is not None:
            config["ransom_note"]["locations"] = request.ransom_note_locations
    
    if request.simulate_vssadmin is not None:
        config["simulate_vssadmin"] = request.simulate_vssadmin
    if request.simulate_persistence is not None:
        config["simulate_persistence"] = request.simulate_persistence
    if request.persistence_type is not None:
        config["persistence_type"] = request.persistence_type
    if request.simulate_exfiltration is not None:
        config["simulate_exfiltration"] = request.simulate_exfiltration
    if request.exfil_target_dir is not None:
        config["exfil_target_dir"] = request.exfil_target_dir
    if request.intensity_level is not None:
        config["intensity_level"] = request.intensity_level
    if request.delay_seconds is not None:
        config["optional_delay_seconds"] = request.delay_seconds
    if request.behavior_style is not None:
        config["behavior_style"] = request.behavior_style
    if request.tags is not None:
        config["tags"] = request.tags
    
    return config


# =============================================================================
# API ENDPOINTS
# =============================================================================

@router.get("", response_model=List[ScenarioSchema])
def list_scenarios(db: Session = Depends(get_db)):
    """
    List all scenarios (both built-in and custom).
    """
    scenarios = crud.get_all_scenarios(db)
    return scenarios


@router.get("/{scenario_id}", response_model=ScenarioSchema)
def get_scenario(scenario_id: int, db: Session = Depends(get_db)):
    """
    Get scenario details by ID.
    """
    scenario = crud.get_scenario_by_id(db, scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


@router.post("", response_model=ScenarioResponse)
def create_scenario(request: ScenarioCreateRequest, db: Session = Depends(get_db)):
    """
    Create a new custom scenario.
    
    All custom scenarios are marked with is_custom=True.
    Built-in scenarios cannot be created via this endpoint.
    """
    # Validate configuration
    errors = validate_scenario_config(request)
    if errors:
        return ScenarioResponse(
            success=False,
            message="Validation failed",
            errors=errors
        )
    
    # Generate unique key
    key = crud.generate_unique_scenario_key(db, request.name)
    
    # Build config JSON
    config = build_config_from_request(request)
    
    # Create scenario
    scenario = crud.create_custom_scenario(
        db=db,
        key=key,
        name=request.name,
        description=request.description or "",
        category=request.category,
        config=config,
        created_by=request.created_by or "admin"
    )
    
    return ScenarioResponse(
        success=True,
        scenario_id=scenario.id,
        message=f"Custom scenario '{scenario.name}' created successfully"
    )


@router.put("/{scenario_id}", response_model=ScenarioResponse)
def update_scenario(
    scenario_id: int,
    request: ScenarioUpdateRequest,
    db: Session = Depends(get_db)
):
    """
    Update an existing custom scenario.
    
    Built-in scenarios cannot be edited.
    """
    scenario = crud.get_scenario_by_id(db, scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    if not scenario.is_custom:
        raise HTTPException(
            status_code=403,
            detail="Built-in scenarios cannot be edited. Clone it to create a custom version."
        )
    
    # Build updated config
    new_config = update_config_from_request(scenario.config or {}, request)
    
    # Update scenario
    updated = crud.update_custom_scenario(
        db=db,
        scenario_id=scenario_id,
        name=request.name,
        description=request.description,
        category=request.category,
        config=new_config
    )
    
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update scenario")
    
    return ScenarioResponse(
        success=True,
        scenario_id=updated.id,
        message=f"Scenario '{updated.name}' updated successfully"
    )


@router.delete("/{scenario_id}", response_model=ScenarioResponse)
def delete_scenario(scenario_id: int, db: Session = Depends(get_db)):
    """
    Delete a custom scenario.
    
    Built-in scenarios cannot be deleted.
    Scenarios with associated runs cannot be deleted.
    """
    scenario = crud.get_scenario_by_id(db, scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    if not scenario.is_custom:
        raise HTTPException(
            status_code=403,
            detail="Built-in scenarios cannot be deleted"
        )
    
    if scenario.runs:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete scenario with associated simulation runs"
        )
    
    success = crud.delete_custom_scenario(db, scenario_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete scenario")
    
    return ScenarioResponse(
        success=True,
        message=f"Scenario deleted successfully"
    )


@router.post("/{scenario_id}/clone", response_model=ScenarioResponse)
def clone_scenario(
    scenario_id: int,
    new_name: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Clone an existing scenario (built-in or custom) into a new custom scenario.
    """
    source = crud.get_scenario_by_id(db, scenario_id)
    if not source:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # Generate name and key for clone
    clone_name = new_name or f"{source.name} (Copy)"
    clone_key = crud.generate_unique_scenario_key(db, clone_name)
    
    cloned = crud.clone_scenario(
        db=db,
        scenario_id=scenario_id,
        new_name=clone_name,
        new_key=clone_key,
        created_by="admin"
    )
    
    if not cloned:
        raise HTTPException(status_code=500, detail="Failed to clone scenario")
    
    return ScenarioResponse(
        success=True,
        scenario_id=cloned.id,
        message=f"Scenario cloned as '{cloned.name}'"
    )


@router.get("/{scenario_id}/export", response_model=ScenarioExportSchema)
def export_scenario(scenario_id: int, db: Session = Depends(get_db)):
    """
    Export a scenario definition as JSON.
    
    Can be used to share scenarios between environments/teams.
    """
    scenario = crud.get_scenario_by_id(db, scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    config = scenario.config or {}
    tags = config.get("tags", [])
    
    return ScenarioExportSchema(
        name=scenario.name,
        key=scenario.key,
        description=scenario.description,
        category=scenario.category.value if scenario.category else "crypto",
        config=config,
        tags=tags
    )


@router.post("/import", response_model=ScenarioResponse)
def import_scenario(request: ScenarioImportRequest, db: Session = Depends(get_db)):
    """
    Import a scenario from JSON definition.
    
    Creates a new custom scenario with the imported configuration.
    A new unique key will be generated.
    """
    # Basic validation of imported config
    config = request.config
    
    # Validate target directories in config
    target_dirs = config.get("directories_to_target", [])
    for dir_path in target_dirs:
        dir_upper = dir_path.upper().rstrip("\\")
        for forbidden in FORBIDDEN_DIRECTORIES:
            if dir_upper == forbidden.upper() or dir_upper.startswith(forbidden.upper() + "\\"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Imported config contains forbidden directory: {dir_path}"
                )
    
    # Validate max_files
    max_files = config.get("max_files", 150)
    if max_files > MAX_FILES_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"Imported config max_files ({max_files}) exceeds limit ({MAX_FILES_LIMIT})"
        )
    
    # Ensure no network exfiltration
    config["simulate_network_beacon"] = False
    
    # Generate unique key
    key = crud.generate_unique_scenario_key(db, request.name)
    
    # Merge tags
    if request.tags:
        config["tags"] = list(set(config.get("tags", []) + request.tags))
    
    # Create scenario
    scenario = crud.create_custom_scenario(
        db=db,
        key=key,
        name=request.name,
        description=request.description or "",
        category=request.category,
        config=config,
        created_by="import"
    )
    
    return ScenarioResponse(
        success=True,
        scenario_id=scenario.id,
        message=f"Scenario '{scenario.name}' imported successfully"
    )


# =============================================================================
# AGENT ENDPOINT
# =============================================================================

@router.get("/by-key/{scenario_key}")
def get_scenario_config_by_key(scenario_key: str, db: Session = Depends(get_db)):
    """
    Get scenario configuration by key.
    
    Used by agents to fetch full scenario config when only given a scenario_key.
    """
    scenario = crud.get_scenario_by_key(db, scenario_key)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    return {
        "scenario_key": scenario.key,
        "scenario_name": scenario.name,
        "scenario_config": scenario.config or {}
    }
