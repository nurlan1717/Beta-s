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


@router.get("/landing", response_class=HTMLResponse)
async def phishing_landing_page(
    request: Request,
    campaign: int = Query(None),
    token: str = Query(None),
    db: Session = Depends(get_db)
):
    """Safe training landing page shown after clicking phishing link."""
    check_phishing_enabled()
    
    campaign_obj = None
    message = None
    
    if token:
        message = phishing_crud.get_message_by_token(db, token)
        if message:
            campaign_obj = message.campaign
    elif campaign:
        campaign_obj = phishing_crud.get_campaign(db, campaign)
    
    return templates.TemplateResponse("phishing_landing.html", {
        "request": request,
        "campaign": campaign_obj,
        "message": message,
        "is_simulation": True
    })


# =============================================================================
# TRACKING ENDPOINT
# =============================================================================

@router.get("/t/{token}")
async def track_click(
    request: Request,
    token: str,
    db: Session = Depends(get_db)
):
    """
    Click tracking endpoint.
    Marks message as CLICKED and redirects to landing page.
    Optionally triggers a safe simulation run.
    """
    message = phishing_crud.get_message_by_token(db, token)
    if not message:
        raise HTTPException(status_code=404, detail="Invalid tracking token")
    
    # Mark as clicked
    phishing_crud.mark_message_clicked(db, message.id, {
        "user_agent": request.headers.get("user-agent"),
        "ip": request.client.host if request.client else None
    })
    
    # Trigger simulation run on phishing click
    campaign = message.campaign
    recipient = message.recipient
    
    print(f"[PHISHING] Click detected - Campaign: {campaign.id}, Scenario: {campaign.scenario_id}, Host: {recipient.host_id}")
    
    # Get host_id - either from recipient or find first available host
    target_host_id = recipient.host_id
    
    # If no host_id on recipient but campaign has scenario, use first available host
    if not target_host_id and campaign.scenario_id:
        all_hosts = crud.get_all_hosts(db)
        if all_hosts:
            target_host_id = all_hosts[0].id
            print(f"[PHISHING] No host on recipient, using first available host: {target_host_id}")
    
    if campaign.scenario_id and target_host_id:
        try:
            print(f"[PHISHING] Triggering ransomware simulation - Scenario: {campaign.scenario_id}, Host: {target_host_id}")
            
            # Create a simulation run
            run = crud.create_run(
                db,
                scenario_id=campaign.scenario_id,
                host_id=target_host_id
            )
            
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
                    "triggered_by": "phishing_campaign",
                    "campaign_id": campaign.id
                },
                run_id=run.id
            )
            print(f"[PHISHING] Ransomware task created successfully for run {run.id}")
        except Exception as e:
            print(f"[PHISHING] Failed to trigger simulation: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"[PHISHING] Cannot trigger simulation - scenario_id: {campaign.scenario_id}, host_id: {target_host_id}")
    
    # Redirect to landing page
    return RedirectResponse(
        url=f"/phishing/landing?campaign={campaign.id}&token={token}",
        status_code=302
    )


# =============================================================================
# API ROUTES
# =============================================================================

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
        if campaign.delivery_mode == DeliveryMode.MAIL_SINK and ENABLE_LOCAL_MAIL_SINK:
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
