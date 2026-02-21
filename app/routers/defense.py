"""
RANSOMRUN Defense API Router
=============================
API endpoints for Blue Team defense tools:
- Canary file management
- Entropy monitoring
- Defense alerts
"""

import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..services.defense_monitor import (
    defense_manager,
    get_folder_entropy,
    get_file_entropy,
    ENTROPY_THRESHOLD,
    DEFAULT_CANARY_FILES
)
from .. import crud


router = APIRouter(prefix="/defense", tags=["Blue Team Defense"])
api_router = APIRouter(prefix="/api/defense", tags=["Defense API"])

templates = Jinja2Templates(directory="app/templates")


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

class DefenseInitRequest(BaseModel):
    target_dir: str = "C:\\RansomTest"
    canary_files: Optional[List[str]] = None


class EntropyCheckRequest(BaseModel):
    path: str


class CanaryDeployRequest(BaseModel):
    target_dir: str = "C:\\RansomTest"
    canary_files: Optional[List[str]] = None


# =============================================================================
# UI ROUTES
# =============================================================================

@router.get("/", response_class=HTMLResponse)
async def defense_dashboard(request: Request, db: Session = Depends(get_db)):
    """Blue Team Defense Dashboard."""
    
    # Get defense status
    status = defense_manager.get_full_status()
    alerts = defense_manager.get_all_alerts()[:20]
    
    # Get entropy data if available
    entropy_history = []
    if defense_manager.entropy_service:
        entropy_history = defense_manager.entropy_service.get_history(30)
    
    return templates.TemplateResponse("defense_dashboard.html", {
        "request": request,
        "status": status,
        "alerts": alerts,
        "entropy_history": entropy_history,
        "entropy_threshold": ENTROPY_THRESHOLD,
        "default_canary_files": DEFAULT_CANARY_FILES
    })


# =============================================================================
# API ROUTES
# =============================================================================

@api_router.post("/initialize")
async def initialize_defense(data: DefenseInitRequest):
    """Initialize defense services with target directory."""
    try:
        defense_manager.initialize(
            target_dir=data.target_dir,
            canary_files=data.canary_files
        )
        return {
            "success": True,
            "message": f"Defense initialized for {data.target_dir}",
            "status": defense_manager.get_full_status()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/canary/deploy")
async def deploy_canaries(data: CanaryDeployRequest):
    """Deploy canary (honeypot) files."""
    try:
        # Initialize if not already done
        if not defense_manager.canary_service:
            defense_manager.initialize(data.target_dir, data.canary_files)
        
        result = defense_manager.deploy_canaries()
        return {
            "success": True,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/canary/start")
async def start_canary_monitoring():
    """Start canary file monitoring."""
    if not defense_manager.canary_service:
        raise HTTPException(status_code=400, detail="Defense not initialized. Call /initialize first.")
    
    success = defense_manager.canary_service.start_monitoring(defense_manager._alert_callback)
    return {
        "success": success,
        "status": defense_manager.canary_service.get_status()
    }


@api_router.post("/canary/stop")
async def stop_canary_monitoring():
    """Stop canary file monitoring."""
    if defense_manager.canary_service:
        defense_manager.canary_service.stop_monitoring()
    return {"success": True, "message": "Canary monitoring stopped"}


@api_router.get("/canary/status")
async def get_canary_status():
    """Get canary defense status."""
    if not defense_manager.canary_service:
        return {"initialized": False}
    return defense_manager.canary_service.get_status()


@api_router.get("/canary/alerts")
async def get_canary_alerts():
    """Get canary alerts."""
    if not defense_manager.canary_service:
        return {"alerts": []}
    return {"alerts": defense_manager.canary_service.get_alerts()}


@api_router.post("/entropy/start")
async def start_entropy_monitoring():
    """Start entropy monitoring."""
    if not defense_manager.entropy_service:
        raise HTTPException(status_code=400, detail="Defense not initialized. Call /initialize first.")
    
    defense_manager.entropy_service.start_monitoring(defense_manager._alert_callback)
    return {
        "success": True,
        "status": defense_manager.entropy_service.get_status()
    }


@api_router.post("/entropy/stop")
async def stop_entropy_monitoring():
    """Stop entropy monitoring."""
    if defense_manager.entropy_service:
        defense_manager.entropy_service.stop_monitoring()
    return {"success": True, "message": "Entropy monitoring stopped"}


@api_router.get("/entropy/status")
async def get_entropy_status():
    """Get entropy monitor status."""
    if not defense_manager.entropy_service:
        return {"initialized": False}
    return defense_manager.entropy_service.get_status()


@api_router.get("/entropy/current")
async def get_current_entropy():
    """Get current entropy reading."""
    if not defense_manager.entropy_service:
        raise HTTPException(status_code=400, detail="Defense not initialized")
    return defense_manager.entropy_service.get_current_entropy()


@api_router.get("/entropy/history")
async def get_entropy_history(limit: int = 50):
    """Get entropy history."""
    if not defense_manager.entropy_service:
        return {"history": []}
    return {"history": defense_manager.entropy_service.get_history(limit)}


@api_router.post("/entropy/check")
async def check_path_entropy(data: EntropyCheckRequest):
    """Check entropy of a specific path (file or folder)."""
    if not os.path.exists(data.path):
        raise HTTPException(status_code=404, detail=f"Path not found: {data.path}")
    
    if os.path.isfile(data.path):
        entropy = get_file_entropy(data.path)
        return {
            "path": data.path,
            "type": "file",
            "entropy": round(entropy, 2),
            "is_encrypted": entropy > ENTROPY_THRESHOLD,
            "threshold": ENTROPY_THRESHOLD
        }
    else:
        result = get_folder_entropy(data.path)
        result["path"] = data.path
        result["type"] = "folder"
        result["threshold"] = ENTROPY_THRESHOLD
        return result


@api_router.post("/start-all")
async def start_all_monitoring(data: DefenseInitRequest):
    """Initialize and start all defense monitoring."""
    try:
        defense_manager.initialize(data.target_dir, data.canary_files)
        
        # Deploy canaries
        deploy_result = defense_manager.deploy_canaries()
        
        # Start monitoring
        monitor_result = defense_manager.start_all_monitoring()
        
        return {
            "success": True,
            "canaries_deployed": deploy_result,
            "monitoring_started": monitor_result,
            "status": defense_manager.get_full_status()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/stop-all")
async def stop_all_monitoring():
    """Stop all defense monitoring."""
    defense_manager.stop_all_monitoring()
    return {"success": True, "message": "All monitoring stopped"}


@api_router.get("/status")
async def get_defense_status():
    """Get full defense status."""
    return defense_manager.get_full_status()


@api_router.get("/alerts")
async def get_all_alerts():
    """Get all defense alerts."""
    return {"alerts": defense_manager.get_all_alerts()}
