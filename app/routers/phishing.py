"""
Phishing Awareness Simulator - API Router
==========================================
Endpoints for phishing awareness training campaigns.

SAFETY REQUIREMENTS:
- No SMTP to real addresses by default
- Only IN_APP delivery or localhost MailHog
- Allowlisted domains only
- All links resolve to internal routes
"""

import os
import csv
import io
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query, UploadFile, File, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from ..database import get_db
from ..models import (
    PhishingCampaign, PhishingRecipient, PhishingMessage, PhishingEvent,
    CampaignStatus, DeliveryMode, PhishingEventType
)
from .. import crud_phishing as phishing_crud
from ..services.phishing_templates import (
    get_all_templates, get_template, render_template, get_template_categories
)
from .. import crud


# =============================================================================
# CONFIGURATION - Safety Controls
# =============================================================================

PHISHING_SIM_ENABLED = os.getenv("PHISHING_SIM_ENABLED", "true").lower() == "true"
PHISHING_DELIVERY_MODE = os.getenv("PHISHING_DELIVERY_MODE", "IN_APP")
ENABLE_LOCAL_MAIL_SINK = os.getenv("ENABLE_LOCAL_MAIL_SINK", "false").lower() == "true"
ALLOWLIST_DOMAINS = os.getenv("ALLOWLIST_DOMAINS", "lab.local,example.local,test.local,ransomrun.local,training.local").split(",")
MAILHOG_HOST = os.getenv("MAILHOG_HOST", "localhost")
MAILHOG_PORT = int(os.getenv("MAILHOG_PORT", "1025"))
PHISHING_BASE_URL = os.getenv("PHISHING_BASE_URL", "http://192.168.10.55:8000")


router = APIRouter(prefix="/phishing", tags=["Phishing Awareness"])
api_router = APIRouter(prefix="/api/phishing", tags=["Phishing API"])

templates = Jinja2Templates(directory="app/templates")


# =============================================================================
# PYDANTIC SCHEMAS
# =============================================================================

class CampaignCreate(BaseModel):
    name: str
    description: Optional[str] = None
    template_key: Optional[str] = None
    delivery_mode: str = "IN_APP"
    target_group_tag: Optional[str] = None
    scenario_id: Optional[int] = None


class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    template_key: Optional[str] = None
    delivery_mode: Optional[str] = None
    target_group_tag: Optional[str] = None
    scenario_id: Optional[int] = None


class RecipientCreate(BaseModel):
    display_name: str
    email: str
    department: Optional[str] = None
    host_id: Optional[int] = None


class MessageResponse(BaseModel):
    id: int
    subject: str
    is_opened: bool
    is_clicked: bool
    is_reported: bool
    sent_at: Optional[datetime]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def check_phishing_enabled():
    """Check if phishing simulation is enabled."""
    if not PHISHING_SIM_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Phishing simulation is disabled. Set PHISHING_SIM_ENABLED=true to enable."
        )


def validate_email_domain(email: str) -> bool:
    """Check if email domain is in allowlist."""
    if not email or "@" not in email:
        return False
    domain = email.split("@")[1].lower()
    return domain in [d.lower().strip() for d in ALLOWLIST_DOMAINS]


def check_delivery_mode(mode: str):
    """Validate delivery mode against config."""
    if mode == "MAIL_SINK" and not ENABLE_LOCAL_MAIL_SINK:
        raise HTTPException(
            status_code=403,
            detail="Mail sink delivery is disabled. Set ENABLE_LOCAL_MAIL_SINK=true to enable."
        )


def send_to_mailhog(recipient_email: str, subject: str, body_html: str):
    """Send email to local MailHog instance (localhost only)."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = "phishing-sim@ransomrun.local"
    msg["To"] = recipient_email
    
    html_part = MIMEText(body_html, "html")
    msg.attach(html_part)
    
    try:
        with smtplib.SMTP(MAILHOG_HOST, MAILHOG_PORT) as server:
            server.sendmail("phishing-sim@ransomrun.local", [recipient_email], msg.as_string())
        return True
    except Exception as e:
        print(f"MailHog send failed: {e}")
        return False


# =============================================================================
# UI ROUTES (Jinja Templates)
# =============================================================================

@router.get("", response_class=HTMLResponse)
async def phishing_campaigns_page(request: Request, db: Session = Depends(get_db)):
    """Campaign list page."""
    check_phishing_enabled()
    
    campaigns = phishing_crud.get_campaigns(db)
    stats = phishing_crud.get_overall_stats(db)
    
    # Get stats for each campaign
    campaign_data = []
    for c in campaigns:
        c_stats = phishing_crud.get_campaign_stats(db, c.id)
        campaign_data.append({
            "campaign": c,
            "stats": c_stats,
            "recipient_count": len(c.recipients)
        })
    
    return templates.TemplateResponse("phishing_campaigns.html", {
        "request": request,
        "campaigns": campaign_data,
        "stats": stats,
        "config": {
            "enabled": PHISHING_SIM_ENABLED,
            "delivery_mode": PHISHING_DELIVERY_MODE,
            "mail_sink_enabled": ENABLE_LOCAL_MAIL_SINK,
            "allowlist_domains": ALLOWLIST_DOMAINS
        }
    })


@router.get("/new", response_class=HTMLResponse)
async def new_campaign_page(request: Request, db: Session = Depends(get_db)):
    """Create campaign form."""
    check_phishing_enabled()
    
    template_list = get_all_templates()
    categories = get_template_categories()
    scenarios = crud.get_all_scenarios(db)
    hosts = crud.get_all_hosts(db)
    
    return templates.TemplateResponse("phishing_campaign_form.html", {
        "request": request,
        "campaign": None,
        "templates": template_list,
        "categories": categories,
        "scenarios": scenarios,
        "hosts": hosts,
        "mail_sink_enabled": ENABLE_LOCAL_MAIL_SINK,
        "allowlist_domains": ALLOWLIST_DOMAINS,
        "is_edit": False
    })


@router.get("/campaign/{campaign_id}", response_class=HTMLResponse)
async def campaign_detail_page(
    request: Request,
    campaign_id: int,
    db: Session = Depends(get_db)
):
    """Campaign detail/edit page."""
    check_phishing_enabled()
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    recipients = phishing_crud.get_recipients_by_campaign(db, campaign_id)
    messages = phishing_crud.get_messages_by_campaign(db, campaign_id)
    stats = phishing_crud.get_campaign_stats(db, campaign_id)
    
    template_list = get_all_templates()
    categories = get_template_categories()
    scenarios = crud.get_all_scenarios(db)
    hosts = crud.get_all_hosts(db)
    
    return templates.TemplateResponse("phishing_campaign_form.html", {
        "request": request,
        "campaign": campaign,
        "recipients": recipients,
        "messages": messages,
        "stats": stats,
        "templates": template_list,
        "categories": categories,
        "scenarios": scenarios,
        "hosts": hosts,
        "mail_sink_enabled": ENABLE_LOCAL_MAIL_SINK,
        "allowlist_domains": ALLOWLIST_DOMAINS,
        "is_edit": True
    })


@router.get("/dashboard", response_class=HTMLResponse)
async def phishing_dashboard_page(request: Request, db: Session = Depends(get_db)):
    """Phishing metrics dashboard."""
    check_phishing_enabled()
    
    stats = phishing_crud.get_overall_stats(db)
    campaigns = phishing_crud.get_campaigns(db)
    
    # Get per-campaign stats
    campaign_stats = []
    for c in campaigns:
        c_stats = phishing_crud.get_campaign_stats(db, c.id)
        campaign_stats.append({
            "campaign": c,
            "stats": c_stats
        })
    
    return templates.TemplateResponse("phishing_dashboard.html", {
        "request": request,
        "stats": stats,
        "campaign_stats": campaign_stats
    })


@router.get("/inbox", response_class=HTMLResponse)
async def phishing_inbox_page(
    request: Request,
    email: str = Query(None),
    db: Session = Depends(get_db)
):
    """In-app inbox for training users."""
    check_phishing_enabled()
    
    # Get all unique recipient emails for dropdown
    all_recipients = db.query(PhishingRecipient).distinct(PhishingRecipient.email).all()
    emails = list(set(r.email for r in all_recipients))
    
    messages = []
    if email:
        messages = phishing_crud.get_inbox_messages(db, email=email)
    
    return templates.TemplateResponse("phishing_inbox.html", {
        "request": request,
        "messages": messages,
        "selected_email": email,
        "available_emails": emails
    })


@router.get("/message/{message_id}", response_class=HTMLResponse)
async def view_message_page(
    request: Request,
    message_id: int,
    db: Session = Depends(get_db)
):
    """View a phishing message (marks as OPENED)."""
    check_phishing_enabled()
    
    message = phishing_crud.get_message(db, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    # Mark as opened
    phishing_crud.mark_message_opened(db, message_id, {
        "user_agent": request.headers.get("user-agent"),
        "ip": request.client.host if request.client else None
    })
    
    return templates.TemplateResponse("phishing_message.html", {
        "request": request,
        "message": message,
        "recipient": message.recipient,
        "campaign": message.campaign
    })


@router.get("/landing/{token}", response_class=HTMLResponse)
async def phishing_landing_page_token(
    request: Request,
    token: str,
    db: Session = Depends(get_db)
):
    """Training landing page with download button - token in path."""
    check_phishing_enabled()
    
    message = phishing_crud.get_message_by_token(db, token)
    if not message:
        raise HTTPException(status_code=404, detail="Invalid or expired link")
    
    campaign = message.campaign
    
    # Determine document type based on template
    doc_types = {
        "invoice": "Invoice Document",
        "hr": "HR Policy Document", 
        "password": "Password Reset Form",
        "delivery": "Delivery Confirmation"
    }
    document_type = "Secure Document"
    if campaign.template_key:
        for key, dtype in doc_types.items():
            if key in campaign.template_key.lower():
                document_type = dtype
                break
    
    return templates.TemplateResponse("phishing_landing_training.html", {
        "request": request,
        "campaign": campaign,
        "message": message,
        "token": token,
        "document_type": document_type,
        "file_size": "24 KB",
        "expiry": "24 hours",
        "is_simulation": True
    })


@router.get("/landing", response_class=HTMLResponse)
async def phishing_landing_page(
    request: Request,
    campaign: int = Query(None),
    token: str = Query(None),
    db: Session = Depends(get_db)
):
    """Legacy landing page - redirects to token-based route if token provided."""
    check_phishing_enabled()
    
    if token:
        return RedirectResponse(url=f"/phishing/landing/{token}", status_code=302)
    
    campaign_obj = None
    if campaign:
        campaign_obj = phishing_crud.get_campaign(db, campaign)
    
    return templates.TemplateResponse("phishing_landing.html", {
        "request": request,
        "campaign": campaign_obj,
        "message": None,
        "is_simulation": True
    })


# =============================================================================
# TRACKING ENDPOINTS
# =============================================================================

# 1x1 transparent PNG pixel for email open tracking
TRACKING_PIXEL = bytes([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
    0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
    0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
])


@router.get("/t/pixel/{token}.png")
async def track_pixel(
    request: Request,
    token: str,
    db: Session = Depends(get_db)
):
    """
    Email open tracking pixel.
    Returns a 1x1 transparent PNG and logs OPENED event.
    """
    from fastapi.responses import Response
    
    message = phishing_crud.get_message_by_token(db, token)
    if message:
        # Mark as opened (idempotent - only logs first open)
        phishing_crud.mark_message_opened(db, message.id, {
            "user_agent": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None
        })
    
    # Always return pixel to avoid detection
    return Response(
        content=TRACKING_PIXEL,
        media_type="image/png",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@router.get("/t/click/{token}")
async def track_click(
    request: Request,
    token: str,
    db: Session = Depends(get_db)
):
    """
    Click tracking endpoint.
    Marks message as CLICKED and redirects to landing page.
    Does NOT trigger simulation - that happens on execute.
    """
    message = phishing_crud.get_message_by_token(db, token)
    if not message:
        raise HTTPException(status_code=404, detail="Invalid tracking token")
    
    # Mark as clicked (idempotent)
    phishing_crud.mark_message_clicked(db, message.id, {
        "user_agent": request.headers.get("user-agent"),
        "ip": request.client.host if request.client else None
    })
    
    campaign = message.campaign
    print(f"[PHISHING] Click tracked - Campaign: {campaign.id}, Token: {token[:8]}...")
    
    # Redirect to landing page with token
    return RedirectResponse(
        url=f"/phishing/landing/{token}",
        status_code=302
    )


@router.get("/t/download/{token}")
async def track_download(
    request: Request,
    token: str,
    db: Session = Depends(get_db)
):
    """
    Download tracking endpoint.
    Marks message as DOWNLOADED and serves the training launcher.
    """
    from fastapi.responses import Response
    
    message = phishing_crud.get_message_by_token(db, token)
    if not message:
        raise HTTPException(status_code=404, detail="Invalid tracking token")
    
    # Mark as downloaded (idempotent)
    phishing_crud.mark_message_downloaded(db, message.id, {
        "user_agent": request.headers.get("user-agent"),
        "ip": request.client.host if request.client else None
    })
    
    campaign = message.campaign
    print(f"[PHISHING] Download tracked - Campaign: {campaign.id}, Token: {token[:8]}...")
    
    # Generate launcher script content with embedded token
    launcher_content = generate_training_launcher(token, campaign.id, campaign.scenario_id)
    
    # Use .bat file for easy execution on Windows
    filename = "SecurityTraining.bat"
    
    return Response(
        content=launcher_content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-RansomRun-Training": "true"
        }
    )


def generate_training_launcher(token: str, campaign_id: int, scenario_id: int = None) -> bytes:
    """
    Generate a benign training launcher batch script.
    This script ONLY:
    1. Calls our backend API to report execution
    2. Displays a training popup
    3. Exits
    
    It does NOT contain any ransomware logic.
    Uses .bat format for easy double-click execution on Windows.
    """
    script = f'''@echo off
title RansomRun Security Awareness Training
color 0B

echo.
echo ============================================
echo   RANSOMRUN SECURITY AWARENESS TRAINING
echo ============================================
echo.
echo This is a TRAINING SIMULATION.
echo You clicked a simulated phishing link and
echo downloaded this file as part of training.
echo.
echo Please wait while we notify the training platform...
echo.

:: Set variables
set TOKEN={token}
set BASEURL=http://192.168.10.55:8000
set CAMPAIGNID={campaign_id}

:: Get system info
set HOSTNAME=%COMPUTERNAME%
set USERNAME=%USERNAME%

:: Notify the training platform using PowerShell (runs in background)
powershell -ExecutionPolicy Bypass -Command "$body = @{{token='{token}';hostname='%COMPUTERNAME%';username='%USERNAME%';campaign_id={campaign_id}}} | ConvertTo-Json; try {{ Invoke-RestMethod -Uri '%BASEURL%/api/phishing/execute' -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop; Write-Host 'Platform notified.' -ForegroundColor Green }} catch {{ Write-Host 'Note: Could not reach platform.' -ForegroundColor Yellow }}"

echo.
echo Training platform notified.
echo.

:: Show the training popup using PowerShell MessageBox
powershell -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('SECURITY AWARENESS TRAINING`n`nYou have just completed a phishing simulation exercise.`n`nWhat happened:`n1. You received a simulated phishing email`n2. You clicked on a suspicious link`n3. You downloaded and ran an unknown file`n`nIn a real attack, this could have installed ransomware or other malware on your computer.`n`nTIPS TO STAY SAFE:`n- Verify sender email addresses carefully`n- Do not click links in unexpected emails`n- Never download files from untrusted sources`n- When in doubt, contact IT Security`n`nThis was a training exercise. No harm was done.`nYour participation helps improve our security posture.`n`nCampaign ID: {campaign_id}', 'RansomRun Security Training', 'OK', 'Information')"

echo.
echo ============================================
echo   Training exercise complete!
echo   Thank you for participating.
echo ============================================
echo.
echo Press any key to close this window...
pause >nul
'''
    return script.encode('utf-8')


# Keep old endpoint for backward compatibility
@router.get("/t/{token}")
async def track_click_legacy(
    request: Request,
    token: str,
    db: Session = Depends(get_db)
):
    """Legacy click tracking - redirects to new endpoint."""
    return RedirectResponse(url=f"/phishing/t/click/{token}", status_code=302)


# =============================================================================
# API ROUTES
# =============================================================================

class ExecuteRequest(BaseModel):
    """Request body for launcher execution."""
    token: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    campaign_id: Optional[int] = None


@api_router.post("/execute")
async def execute_launcher(
    data: ExecuteRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Execute endpoint called by the training launcher.
    Marks message as EXECUTED and optionally triggers simulation.
    
    SAFETY: Only triggers simulation on pre-configured sandbox directories.
    """
    check_phishing_enabled()
    
    message = phishing_crud.get_message_by_token(db, data.token)
    if not message:
        raise HTTPException(status_code=404, detail="Invalid token")
    
    campaign = message.campaign
    recipient = message.recipient
    
    print(f"[PHISHING] Execute called - Campaign: {campaign.id}, Host: {data.hostname}, User: {data.username}")
    
    # Mark as executed
    meta = {
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "hostname": data.hostname,
        "username": data.username
    }
    
    run_id = None
    simulation_started = False
    
    # Trigger simulation if campaign has scenario configured
    if campaign.scenario_id:
        # Find host by hostname or use recipient's configured host
        target_host_id = recipient.host_id
        
        if data.hostname and not target_host_id:
            # Try to find host by hostname (Host model uses 'name' field)
            from ..models import Host
            host = db.query(Host).filter(Host.name == data.hostname).first()
            if host:
                target_host_id = host.id
                print(f"[PHISHING] Found host by hostname: {target_host_id}")
        
        # Fallback to first available host
        if not target_host_id:
            all_hosts = crud.get_all_hosts(db)
            if all_hosts:
                target_host_id = all_hosts[0].id
                print(f"[PHISHING] Using first available host: {target_host_id}")
        
        if target_host_id:
            try:
                # Create simulation run
                run = crud.create_run(
                    db,
                    scenario_id=campaign.scenario_id,
                    host_id=target_host_id
                )
                run_id = run.id
                
                # Get scenario config
                scenario = crud.get_scenario_by_id(db, campaign.scenario_id)
                
                # Create task for the agent
                crud.create_task(
                    db,
                    host_id=target_host_id,
                    task_type="simulate_ransomware",
                    parameters={
                        "scenario_key": scenario.key if scenario else "crypto_basic",
                        "scenario_config": scenario.config if scenario else {},
                        "run_id": run.id,
                        "triggered_by": "phishing_launcher",
                        "campaign_id": campaign.id,
                        "phishing_token": data.token[:16] + "..."
                    },
                    run_id=run.id
                )
                
                simulation_started = True
                print(f"[PHISHING] Simulation triggered - Run ID: {run_id}")
                
                # Update message with simulation run link
                phishing_crud.mark_simulation_started(db, message.id, run_id, meta)
                
            except Exception as e:
                print(f"[PHISHING] Failed to trigger simulation: {e}")
                import traceback
                traceback.print_exc()
    
    # Mark message as executed
    phishing_crud.mark_message_executed(
        db, message.id,
        hostname=data.hostname,
        simulation_run_id=run_id,
        meta=meta
    )
    
    return {
        "success": True,
        "message": "Execution recorded",
        "simulation_started": simulation_started,
        "run_id": run_id,
        "campaign_id": campaign.id
    }


@api_router.post("/campaigns")
async def create_campaign(
    data: CampaignCreate,
    db: Session = Depends(get_db)
):
    """Create a new campaign."""
    check_phishing_enabled()
    check_delivery_mode(data.delivery_mode)
    
    delivery_mode = DeliveryMode.IN_APP
    if data.delivery_mode == "MAIL_SINK":
        delivery_mode = DeliveryMode.MAIL_SINK
    
    campaign = phishing_crud.create_campaign(
        db,
        name=data.name,
        description=data.description,
        template_key=data.template_key,
        delivery_mode=delivery_mode,
        target_group_tag=data.target_group_tag,
        scenario_id=data.scenario_id
    )
    
    return {"success": True, "campaign_id": campaign.id}


@api_router.put("/campaigns/{campaign_id}")
async def update_campaign(
    campaign_id: int,
    data: CampaignUpdate,
    db: Session = Depends(get_db)
):
    """Update a campaign."""
    check_phishing_enabled()
    
    update_data = data.dict(exclude_unset=True)
    
    if "delivery_mode" in update_data:
        check_delivery_mode(update_data["delivery_mode"])
        update_data["delivery_mode"] = DeliveryMode(update_data["delivery_mode"])
    
    campaign = phishing_crud.update_campaign(db, campaign_id, **update_data)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return {"success": True}


@api_router.delete("/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """Delete a campaign."""
    check_phishing_enabled()
    
    if not phishing_crud.delete_campaign(db, campaign_id):
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return {"success": True}


@api_router.post("/campaigns/{campaign_id}/recipients")
async def add_recipient(
    campaign_id: int,
    data: RecipientCreate,
    db: Session = Depends(get_db)
):
    """Add a recipient to a campaign."""
    check_phishing_enabled()
    
    # Validate email domain
    if not validate_email_domain(data.email):
        raise HTTPException(
            status_code=400,
            detail=f"Email domain not allowed. Allowed domains: {', '.join(ALLOWLIST_DOMAINS)}"
        )
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    recipient = phishing_crud.create_recipient(
        db,
        campaign_id=campaign_id,
        display_name=data.display_name,
        email=data.email,
        department=data.department,
        host_id=data.host_id,
        allowlisted=True
    )
    
    return {"success": True, "recipient_id": recipient.id}


@api_router.post("/recipients/import")
async def import_recipients(
    campaign_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Import recipients from CSV file."""
    check_phishing_enabled()
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Read CSV
    content = await file.read()
    decoded = content.decode("utf-8")
    reader = csv.DictReader(io.StringIO(decoded))
    
    imported = 0
    rejected = 0
    errors = []
    
    for row in reader:
        email = row.get("email", "").strip()
        display_name = row.get("display_name", row.get("name", "Unknown")).strip()
        department = row.get("department", "").strip()
        
        if not email:
            continue
        
        # Validate domain
        if not validate_email_domain(email):
            rejected += 1
            errors.append(f"Rejected {email}: domain not in allowlist")
            continue
        
        # Check if already exists
        existing = phishing_crud.get_recipient_by_email(db, campaign_id, email)
        if existing:
            rejected += 1
            errors.append(f"Skipped {email}: already exists")
            continue
        
        phishing_crud.create_recipient(
            db,
            campaign_id=campaign_id,
            display_name=display_name,
            email=email,
            department=department if department else None,
            allowlisted=True
        )
        imported += 1
    
    return {
        "success": True,
        "imported": imported,
        "rejected": rejected,
        "errors": errors[:10]  # Limit error messages
    }


@api_router.delete("/recipients/{recipient_id}")
async def delete_recipient(recipient_id: int, db: Session = Depends(get_db)):
    """Delete a recipient."""
    check_phishing_enabled()
    
    if not phishing_crud.delete_recipient(db, recipient_id):
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    return {"success": True}


@api_router.post("/campaigns/{campaign_id}/launch")
async def launch_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    request: Request = None
):
    """Generate messages and launch campaign."""
    check_phishing_enabled()
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    if campaign.status == CampaignStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Campaign is already running")
    
    recipients = phishing_crud.get_recipients_by_campaign(db, campaign_id)
    if not recipients:
        raise HTTPException(status_code=400, detail="No recipients in campaign")
    
    # Get template
    template = get_template(campaign.template_key) if campaign.template_key else None
    if not template:
        # Use default template
        template = get_template("password_reset_it")
    
    # Generate messages for each recipient
    messages_created = 0
    base_url = PHISHING_BASE_URL
    
    for recipient in recipients:
        # Generate tracking link
        token = phishing_crud.generate_tracking_token()
        tracking_link = f"{base_url}/phishing/t/{token}"
        
        # Render template
        rendered = render_template(
            template,
            recipient_name=recipient.display_name,
            tracking_link=tracking_link,
            sender_name="IT Support"
        )
        
        # Create message
        message = phishing_crud.create_message(
            db,
            campaign_id=campaign_id,
            recipient_id=recipient.id,
            subject=rendered["subject"],
            body_html=rendered["body_html"],
            body_text=rendered["body_text"],
            delivery_mode=campaign.delivery_mode
        )
        
        # Update token (we generated it before creating)
        message.tracking_token = token
        db.commit()
        
        # Deliver based on mode
        if campaign.delivery_mode == DeliveryMode.SMTP:
            # Send via SMTP
            try:
                from ..services.email_service import send_training_email
                result = send_training_email(
                    to_email=recipient.email,
                    to_name=recipient.display_name,
                    subject=rendered["subject"],
                    body_html=rendered["body_html"],
                    body_text=rendered.get("body_text"),
                    token=token,
                    campaign_id=campaign_id
                )
                if result["success"]:
                    phishing_crud.mark_message_sent(db, message.id)
                else:
                    print(f"[PHISHING] SMTP send failed: {result.get('error')}")
            except Exception as e:
                print(f"[PHISHING] SMTP error: {e}")
        elif campaign.delivery_mode == DeliveryMode.MAIL_SINK and ENABLE_LOCAL_MAIL_SINK:
            success = send_to_mailhog(recipient.email, rendered["subject"], rendered["body_html"])
            if success:
                phishing_crud.mark_message_sent(db, message.id)
        else:
            # IN_APP mode - just mark as sent (visible in inbox)
            phishing_crud.mark_message_sent(db, message.id)
        
        messages_created += 1
    
    # Update campaign status
    phishing_crud.launch_campaign(db, campaign_id)
    
    return {
        "success": True,
        "messages_created": messages_created,
        "delivery_mode": campaign.delivery_mode.value
    }


@api_router.post("/campaigns/{campaign_id}/end")
async def end_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """End a running campaign."""
    check_phishing_enabled()
    
    campaign = phishing_crud.end_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return {"success": True}


@api_router.post("/report/{message_id}")
async def report_phishing(
    message_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """Mark a message as reported (user reported phishing)."""
    check_phishing_enabled()
    
    message = phishing_crud.mark_message_reported(db, message_id, {
        "user_agent": request.headers.get("user-agent"),
        "ip": request.client.host if request.client else None
    })
    
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    return {"success": True, "message": "Thank you for reporting this phishing attempt!"}


@api_router.get("/campaigns/{campaign_id}/stats")
async def get_campaign_stats(campaign_id: int, db: Session = Depends(get_db)):
    """Get campaign statistics."""
    check_phishing_enabled()
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    stats = phishing_crud.get_campaign_stats(db, campaign_id)
    return stats


@api_router.get("/stats")
async def get_overall_stats(db: Session = Depends(get_db)):
    """Get overall phishing simulation statistics."""
    check_phishing_enabled()
    
    stats = phishing_crud.get_overall_stats(db)
    return stats


@api_router.get("/templates")
async def list_templates():
    """Get available phishing templates."""
    check_phishing_enabled()
    
    templates_list = get_all_templates()
    return [
        {
            "key": t.key,
            "name": t.name,
            "category": t.category,
            "description": t.description,
            "has_attachment": t.has_attachment
        }
        for t in templates_list
    ]


@api_router.get("/ai/status")
async def get_ai_status():
    """Check if AI rewriting features are available."""
    check_phishing_enabled()
    
    from ..services.ai_rewriter import check_ai_available
    return check_ai_available()


@api_router.post("/ai/rewrite")
async def rewrite_with_ai(
    template_key: str = Form(None),
    subject: str = Form(None),
    body_text: str = Form(None),
    target_industry: str = Form(None),
    target_role: str = Form(None)
):
    """
    Rewrite a template using AI for clarity and professionalism.
    
    SAFETY: AI is constrained to only improve clarity, not make
    content more deceptive. [SIMULATION] banner is preserved.
    """
    check_phishing_enabled()
    
    from ..services.ai_rewriter import rewrite_template_with_ai, check_ai_available
    
    status = check_ai_available()
    if not status["available"]:
        raise HTTPException(
            status_code=503,
            detail="AI rewriting is not available. Check API key and library installation."
        )
    
    # If template_key provided, get the template content
    if template_key and not (subject and body_text):
        template = get_template(template_key)
        if template:
            subject = template.subject
            body_text = template.body_text
    
    if not subject or not body_text:
        raise HTTPException(status_code=400, detail="Subject and body_text are required")
    
    result = rewrite_template_with_ai(
        subject=subject,
        body_text=body_text,
        target_industry=target_industry,
        target_role=target_role
    )
    
    if result:
        return {"success": True, "rewritten": result}
    else:
        return {"success": False, "message": "AI rewrite failed. Using original template."}


@api_router.post("/ai/generate")
async def generate_custom_template_ai(
    scenario_type: str = Form(...),
    target_industry: str = Form("General"),
    target_role: str = Form("Employee")
):
    """
    Generate a custom phishing template using AI.
    
    SAFETY: Generated content is strictly controlled to be
    training-appropriate only with [SIMULATION] banner.
    """
    check_phishing_enabled()
    
    from ..services.ai_rewriter import generate_custom_template, check_ai_available
    
    status = check_ai_available()
    if not status["available"]:
        raise HTTPException(
            status_code=503,
            detail="AI generation is not available. Check API key and library installation."
        )
    
    result = generate_custom_template(
        scenario_type=scenario_type,
        target_industry=target_industry,
        target_role=target_role
    )
    
    if result:
        return {"success": True, "template": result}
    else:
        return {"success": False, "message": "AI generation failed."}


# =============================================================================
# SETTINGS API
# =============================================================================

@api_router.get("/settings")
async def get_all_settings(db: Session = Depends(get_db)):
    """Get all phishing settings."""
    check_phishing_enabled()
    
    # Seed defaults if not exist
    phishing_crud.seed_default_settings(db)
    
    settings = phishing_crud.get_all_settings(db)
    return {"success": True, "settings": settings}


@api_router.put("/settings/{key}")
async def update_setting(
    key: str,
    value: str = Form(...),
    setting_type: str = Form("string"),
    db: Session = Depends(get_db)
):
    """Update a single setting."""
    check_phishing_enabled()
    
    phishing_crud.set_setting(db, key, value, setting_type)
    return {"success": True}


@api_router.get("/settings/allowed-domains")
async def get_allowed_domains(db: Session = Depends(get_db)):
    """Get list of allowed recipient domains."""
    check_phishing_enabled()
    
    domains = phishing_crud.get_allowed_domains(db)
    return {"success": True, "domains": domains}


@api_router.put("/settings/allowed-domains")
async def update_allowed_domains(
    domains: List[str],
    db: Session = Depends(get_db)
):
    """Update allowed recipient domains."""
    check_phishing_enabled()
    
    phishing_crud.set_setting(db, "allowed_domains", domains, "json")
    return {"success": True, "domains": domains}


# =============================================================================
# DB TEMPLATES API
# =============================================================================

@api_router.get("/db-templates")
async def get_db_templates(
    category: str = Query(None),
    db: Session = Depends(get_db)
):
    """Get templates stored in database."""
    check_phishing_enabled()
    
    # Seed defaults if none exist
    phishing_crud.seed_default_templates(db)
    
    templates_list = phishing_crud.get_all_templates(db, category=category)
    return {
        "success": True,
        "templates": [
            {
                "id": t.id,
                "key": t.key,
                "name": t.name,
                "category": t.category,
                "description": t.description,
                "subject": t.subject,
                "has_attachment": t.has_attachment,
                "landing_page_type": t.landing_page_type
            }
            for t in templates_list
        ]
    }


@api_router.get("/db-templates/{template_id}")
async def get_db_template(template_id: int, db: Session = Depends(get_db)):
    """Get a specific template by ID."""
    check_phishing_enabled()
    
    template = phishing_crud.get_template_by_id(db, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    
    return {
        "success": True,
        "template": {
            "id": template.id,
            "key": template.key,
            "name": template.name,
            "category": template.category,
            "description": template.description,
            "subject": template.subject,
            "body_html": template.body_html,
            "body_text": template.body_text,
            "variables": template.variables,
            "has_attachment": template.has_attachment,
            "attachment_name": template.attachment_name,
            "landing_page_type": template.landing_page_type
        }
    }


class TemplateCreate(BaseModel):
    name: str
    key: str
    subject: str
    body_html: str
    body_text: Optional[str] = None
    category: str = "custom"
    description: Optional[str] = None
    variables: Optional[List[str]] = None
    has_attachment: bool = False
    attachment_name: Optional[str] = None
    landing_page_type: str = "document"


@api_router.post("/db-templates")
async def create_db_template(
    data: TemplateCreate,
    db: Session = Depends(get_db)
):
    """Create a new template in database."""
    check_phishing_enabled()
    
    # Check if key already exists
    existing = phishing_crud.get_template_by_key(db, data.key)
    if existing:
        raise HTTPException(status_code=400, detail="Template key already exists")
    
    template = phishing_crud.create_template(
        db,
        name=data.name,
        key=data.key,
        subject=data.subject,
        body_html=data.body_html,
        body_text=data.body_text,
        category=data.category,
        description=data.description,
        variables=data.variables,
        has_attachment=data.has_attachment,
        attachment_name=data.attachment_name,
        landing_page_type=data.landing_page_type
    )
    
    return {"success": True, "template_id": template.id}


@api_router.delete("/db-templates/{template_id}")
async def delete_db_template(template_id: int, db: Session = Depends(get_db)):
    """Delete a template (soft delete)."""
    check_phishing_enabled()
    
    if not phishing_crud.delete_template(db, template_id):
        raise HTTPException(status_code=404, detail="Template not found")
    
    return {"success": True}


# =============================================================================
# CAMPAIGN FUNNEL / TIMELINE API
# =============================================================================

@api_router.get("/campaigns/{campaign_id}/funnel")
async def get_campaign_funnel(campaign_id: int, db: Session = Depends(get_db)):
    """Get campaign funnel metrics for visualization."""
    check_phishing_enabled()
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    stats = phishing_crud.get_campaign_stats(db, campaign_id)
    
    # Build funnel data
    funnel = [
        {"stage": "Sent", "count": stats["sent"], "color": "#6366f1"},
        {"stage": "Opened", "count": stats["opened"], "color": "#8b5cf6"},
        {"stage": "Clicked", "count": stats["clicked"], "color": "#a855f7"},
        {"stage": "Downloaded", "count": stats["downloaded"], "color": "#d946ef"},
        {"stage": "Executed", "count": stats["executed"], "color": "#ec4899"},
        {"stage": "Simulation", "count": stats["simulations_triggered"], "color": "#f43f5e"},
        {"stage": "Reported", "count": stats["reported"], "color": "#22c55e"},
    ]
    
    return {"success": True, "funnel": funnel, "stats": stats}


@api_router.get("/campaigns/{campaign_id}/timeline")
async def get_campaign_timeline(campaign_id: int, db: Session = Depends(get_db)):
    """Get campaign event timeline."""
    check_phishing_enabled()
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    events = phishing_crud.get_events_by_campaign(db, campaign_id)
    
    timeline = []
    for event in events:
        message = event.message
        recipient = message.recipient if message else None
        
        timeline.append({
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "event_type": event.event_type.value if event.event_type else None,
            "recipient_email": recipient.email if recipient else None,
            "recipient_name": recipient.display_name if recipient else None,
            "ip_address": event.ip_address,
            "hostname": event.hostname,
            "message_id": event.message_id
        })
    
    return {"success": True, "timeline": timeline}


@api_router.get("/campaigns/{campaign_id}/targets")
async def get_campaign_targets(campaign_id: int, db: Session = Depends(get_db)):
    """Get detailed target status for a campaign."""
    check_phishing_enabled()
    
    campaign = phishing_crud.get_campaign(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    messages = phishing_crud.get_messages_by_campaign(db, campaign_id)
    
    targets = []
    for msg in messages:
        recipient = msg.recipient
        targets.append({
            "message_id": msg.id,
            "recipient_id": recipient.id if recipient else None,
            "email": recipient.email if recipient else None,
            "name": recipient.display_name if recipient else None,
            "department": recipient.department if recipient else None,
            "host_id": recipient.host_id if recipient else None,
            "status": msg.status,
            "sent_at": msg.sent_at.isoformat() if msg.sent_at else None,
            "is_opened": msg.is_opened,
            "opened_at": msg.opened_at.isoformat() if msg.opened_at else None,
            "is_clicked": msg.is_clicked,
            "clicked_at": msg.clicked_at.isoformat() if msg.clicked_at else None,
            "is_downloaded": getattr(msg, 'is_downloaded', False),
            "downloaded_at": getattr(msg, 'downloaded_at', None),
            "is_executed": getattr(msg, 'is_executed', False),
            "executed_at": getattr(msg, 'executed_at', None),
            "is_reported": msg.is_reported,
            "reported_at": msg.reported_at.isoformat() if msg.reported_at else None,
            "simulation_run_id": getattr(msg, 'simulation_run_id', None)
        })
    
    return {"success": True, "targets": targets}


# =============================================================================
# SEED DATA ENDPOINT
# =============================================================================

@api_router.post("/seed")
async def seed_phishing_data(db: Session = Depends(get_db)):
    """Seed default templates and settings."""
    check_phishing_enabled()
    
    templates_created = phishing_crud.seed_default_templates(db)
    settings_created = phishing_crud.seed_default_settings(db)
    
    return {
        "success": True,
        "templates_created": templates_created,
        "settings_created": settings_created
    }
