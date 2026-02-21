"""
RANSOMRUN - Ransomware Simulation Lab Platform
Main FastAPI Application
"""

import os
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .database import init_db, SessionLocal
from .seed import run_seed
from .routers import agents, alerts, runs, ui, siem, advanced, recovery, scenarios, elk, alerts_stream, phishing, defense, playbooks, backup, isolation
from .auth import routes as auth_routes
from .deps.auth import get_current_user_optional

logger = logging.getLogger(__name__)

# Detection engine instance (initialized in lifespan)
_detection_engine = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    global _detection_engine
    
    print("=" * 50)
    print("  RANSOMRUN - Starting up...")
    print("=" * 50)
    
    # Initialize database tables
    init_db()
    print("[STARTUP] Database initialized")
    
    # Seed initial data
    db = SessionLocal()
    try:
        run_seed(db)
        # Seed advanced playbooks
        from .seed_playbooks import seed_playbooks
        seed_playbooks(db)
    finally:
        db.close()
    
    # Start detection engine if SIEM_MODE is 'elastic'
    siem_mode = os.getenv('SIEM_MODE', 'mock').lower()
    if siem_mode == 'elastic':
        try:
            from .integrations.elk_client import get_elk_client_from_env
            from .detection.engine import DetectionEngine, set_detection_engine
            
            elk_client = get_elk_client_from_env()
            _detection_engine = DetectionEngine(
                elk_client=elk_client,
                db_session_factory=SessionLocal,
                poll_interval=3.0
            )
            await _detection_engine.start()
            set_detection_engine(_detection_engine)
            print("[STARTUP] Detection engine started (LIVE ELK mode)")
        except Exception as e:
            logger.error(f"Failed to start detection engine: {e}")
            print(f"[STARTUP] Detection engine failed: {e}")
    else:
        print("[STARTUP] Detection engine skipped (MOCK mode)")
    
    print("[STARTUP] Ready to accept connections")
    print("=" * 50)
    
    yield  # Application runs here
    
    # Shutdown
    print("[SHUTDOWN] Stopping services...")
    if _detection_engine:
        await _detection_engine.stop()
        print("[SHUTDOWN] Detection engine stopped")
    print("[SHUTDOWN] Complete")


# Create FastAPI app with lifespan
app = FastAPI(
    title="RANSOMRUN",
    description="Ransomware Simulation Lab Platform for Security Training",
    version="3.2.0",
    lifespan=lifespan
)

# Session middleware for authentication (must be before other middleware)
import secrets
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# CORS middleware - allow frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Templates for rendering
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(auth_routes.router)  # Authentication routes (login, signup, etc.)
app.include_router(agents.router)
app.include_router(alerts.router)
app.include_router(runs.router)
app.include_router(ui.router)
app.include_router(siem.router)
app.include_router(advanced.router)
app.include_router(recovery.router)
app.include_router(scenarios.router)
app.include_router(elk.router)
app.include_router(alerts_stream.router)
app.include_router(phishing.router)
app.include_router(phishing.api_router)
app.include_router(defense.router)
app.include_router(defense.api_router)
app.include_router(playbooks.router)
app.include_router(backup.router)
app.include_router(isolation.router)


# Public home/landing page
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Public landing page."""
    user = get_current_user_optional(request)
    
    # If logged in, redirect to dashboard
    if user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/dashboard", status_code=303)
    
    # Show public landing page
    return templates.TemplateResponse("public_home.html", {
        "request": request,
        "user": user
    })


# Docs page (simple placeholder)
@app.get("/docs-page", response_class=HTMLResponse)
async def docs_page(request: Request):
    """Documentation page."""
    user = get_current_user_optional(request)
    return templates.TemplateResponse("base_public.html", {
        "request": request,
        "user": user
    })


@app.get("/api/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "RANSOMRUN"}


# API documentation info
@app.get("/api")
def api_info():
    """API information endpoint."""
    return {
        "name": "RANSOMRUN API",
        "version": "1.0.0",
        "endpoints": {
            "agent": {
                "register": "POST /api/agent/register",
                "get_tasks": "GET /api/agent/tasks?agent_id=...",
                "report_result": "POST /api/agent/task-result"
            },
            "alerts": {
                "wazuh_webhook": "POST /api/alerts/wazuh",
                "list_alerts": "GET /api/alerts/"
            },
            "simulation": {
                "start_run": "POST /api/run-simulation",
                "list_runs": "GET /api/runs",
                "get_run": "GET /api/runs/{run_id}"
            },
            "data": {
                "list_hosts": "GET /api/hosts",
                "get_host": "GET /api/hosts/{host_id}",
                "list_scenarios": "GET /api/scenarios",
                "list_playbooks": "GET /api/playbooks"
            }
        },
        "web_ui": "http://localhost:8000/"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
