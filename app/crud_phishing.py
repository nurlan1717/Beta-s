"""
Phishing Awareness Simulator - CRUD Operations
===============================================
Database operations for phishing campaigns, recipients, messages, and events.
"""

import secrets
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from .models import (
    PhishingCampaign, PhishingRecipient, PhishingMessage, PhishingEvent,
    PhishingTemplate, PhishingSettings,
    CampaignStatus, DeliveryMode, PhishingEventType
)


# =============================================================================
# CAMPAIGN CRUD
# =============================================================================

def create_campaign(
    db: Session,
    name: str,
    description: str = None,
    template_key: str = None,
    delivery_mode: DeliveryMode = DeliveryMode.IN_APP,
    target_group_tag: str = None,
    scenario_id: int = None,
    created_by: str = "admin"
) -> PhishingCampaign:
    """Create a new phishing campaign."""
    campaign = PhishingCampaign(
        name=name,
        description=description,
        template_key=template_key,
        delivery_mode=delivery_mode,
        target_group_tag=target_group_tag,
        scenario_id=scenario_id,
        created_by=created_by,
        status=CampaignStatus.DRAFT
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    return campaign


def get_campaign(db: Session, campaign_id: int) -> Optional[PhishingCampaign]:
    """Get a campaign by ID."""
    return db.query(PhishingCampaign).filter(PhishingCampaign.id == campaign_id).first()


def get_campaigns(
    db: Session,
    status: CampaignStatus = None,
    skip: int = 0,
    limit: int = 100
) -> List[PhishingCampaign]:
    """Get all campaigns, optionally filtered by status."""
    query = db.query(PhishingCampaign)
    if status:
        query = query.filter(PhishingCampaign.status == status)
    return query.order_by(PhishingCampaign.created_at.desc()).offset(skip).limit(limit).all()


def update_campaign(
    db: Session,
    campaign_id: int,
    **kwargs
) -> Optional[PhishingCampaign]:
    """Update a campaign."""
    campaign = get_campaign(db, campaign_id)
    if not campaign:
        return None
    
    for key, value in kwargs.items():
        if hasattr(campaign, key):
            setattr(campaign, key, value)
    
    db.commit()
    db.refresh(campaign)
    return campaign


def delete_campaign(db: Session, campaign_id: int) -> bool:
    """Delete a campaign and all related data."""
    campaign = get_campaign(db, campaign_id)
    if not campaign:
        return False
    
    db.delete(campaign)
    db.commit()
    return True


def launch_campaign(db: Session, campaign_id: int) -> Optional[PhishingCampaign]:
    """Launch a campaign (change status to RUNNING)."""
    campaign = get_campaign(db, campaign_id)
    if not campaign:
        return None
    
    campaign.status = CampaignStatus.RUNNING
    campaign.started_at = datetime.utcnow()
    db.commit()
    db.refresh(campaign)
    return campaign


def end_campaign(db: Session, campaign_id: int) -> Optional[PhishingCampaign]:
    """End a campaign."""
    campaign = get_campaign(db, campaign_id)
    if not campaign:
        return None
    
    campaign.status = CampaignStatus.ENDED
    campaign.ended_at = datetime.utcnow()
    db.commit()
    db.refresh(campaign)
    return campaign


# =============================================================================
# RECIPIENT CRUD
# =============================================================================

def create_recipient(
    db: Session,
    campaign_id: int,
    display_name: str,
    email: str,
    department: str = None,
    host_id: int = None,
    allowlisted: bool = False
) -> PhishingRecipient:
    """Create a new recipient."""
    recipient = PhishingRecipient(
        campaign_id=campaign_id,
        display_name=display_name,
        email=email,
        department=department,
        host_id=host_id,
        allowlisted=allowlisted
    )
    db.add(recipient)
    db.commit()
    db.refresh(recipient)
    return recipient


def get_recipient(db: Session, recipient_id: int) -> Optional[PhishingRecipient]:
    """Get a recipient by ID."""
    return db.query(PhishingRecipient).filter(PhishingRecipient.id == recipient_id).first()


def get_recipients_by_campaign(
    db: Session,
    campaign_id: int
) -> List[PhishingRecipient]:
    """Get all recipients for a campaign."""
    return db.query(PhishingRecipient).filter(
        PhishingRecipient.campaign_id == campaign_id
    ).all()


def get_recipient_by_email(
    db: Session,
    campaign_id: int,
    email: str
) -> Optional[PhishingRecipient]:
    """Get a recipient by email within a campaign."""
    return db.query(PhishingRecipient).filter(
        and_(
            PhishingRecipient.campaign_id == campaign_id,
            PhishingRecipient.email == email
        )
    ).first()


def bulk_create_recipients(
    db: Session,
    campaign_id: int,
    recipients: List[Dict[str, Any]]
) -> List[PhishingRecipient]:
    """Bulk create recipients from a list of dicts."""
    created = []
    for r in recipients:
        recipient = PhishingRecipient(
            campaign_id=campaign_id,
            display_name=r.get("display_name", "Unknown"),
            email=r.get("email"),
            department=r.get("department"),
            host_id=r.get("host_id"),
            allowlisted=r.get("allowlisted", False)
        )
        db.add(recipient)
        created.append(recipient)
    
    db.commit()
    for r in created:
        db.refresh(r)
    return created


def delete_recipient(db: Session, recipient_id: int) -> bool:
    """Delete a recipient."""
    recipient = get_recipient(db, recipient_id)
    if not recipient:
        return False
    
    db.delete(recipient)
    db.commit()
    return True


# =============================================================================
# MESSAGE CRUD
# =============================================================================

def generate_tracking_token() -> str:
    """Generate a unique tracking token."""
    return secrets.token_urlsafe(32)


def create_message(
    db: Session,
    campaign_id: int,
    recipient_id: int,
    subject: str,
    body_html: str,
    body_text: str = None,
    delivery_mode: DeliveryMode = DeliveryMode.IN_APP
) -> PhishingMessage:
    """Create a new phishing message."""
    message = PhishingMessage(
        campaign_id=campaign_id,
        recipient_id=recipient_id,
        subject=subject,
        body_html=body_html,
        body_text=body_text,
        tracking_token=generate_tracking_token(),
        delivery_mode=delivery_mode,
        status="PENDING"
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message


def get_message(db: Session, message_id: int) -> Optional[PhishingMessage]:
    """Get a message by ID."""
    return db.query(PhishingMessage).filter(PhishingMessage.id == message_id).first()


def get_message_by_token(db: Session, token: str) -> Optional[PhishingMessage]:
    """Get a message by tracking token."""
    return db.query(PhishingMessage).filter(PhishingMessage.tracking_token == token).first()


def get_messages_by_campaign(
    db: Session,
    campaign_id: int
) -> List[PhishingMessage]:
    """Get all messages for a campaign."""
    return db.query(PhishingMessage).filter(
        PhishingMessage.campaign_id == campaign_id
    ).all()


def get_messages_for_recipient_email(
    db: Session,
    email: str
) -> List[PhishingMessage]:
    """Get all messages for a recipient by email (for inbox view)."""
    return db.query(PhishingMessage).join(PhishingRecipient).filter(
        PhishingRecipient.email == email
    ).order_by(PhishingMessage.created_at.desc()).all()


def get_inbox_messages(
    db: Session,
    email: str = None,
    campaign_id: int = None
) -> List[PhishingMessage]:
    """Get inbox messages, optionally filtered."""
    query = db.query(PhishingMessage).filter(
        PhishingMessage.status == "SENT"
    )
    
    if email:
        query = query.join(PhishingRecipient).filter(
            PhishingRecipient.email == email
        )
    
    if campaign_id:
        query = query.filter(PhishingMessage.campaign_id == campaign_id)
    
    return query.order_by(PhishingMessage.sent_at.desc()).all()


def mark_message_sent(db: Session, message_id: int) -> Optional[PhishingMessage]:
    """Mark a message as sent."""
    message = get_message(db, message_id)
    if not message:
        return None
    
    message.status = "SENT"
    message.sent_at = datetime.utcnow()
    db.commit()
    db.refresh(message)
    
    # Create SENT event
    create_event(db, message_id, PhishingEventType.SENT)
    
    return message


def mark_message_opened(db: Session, message_id: int, meta: dict = None) -> Optional[PhishingMessage]:
    """Mark a message as opened."""
    message = get_message(db, message_id)
    if not message:
        return None
    
    if not message.is_opened:
        message.is_opened = True
        message.opened_at = datetime.utcnow()
        db.commit()
        db.refresh(message)
        
        # Create OPENED event
        create_event(db, message_id, PhishingEventType.OPENED, meta)
    
    return message


def mark_message_clicked(db: Session, message_id: int, meta: dict = None) -> Optional[PhishingMessage]:
    """Mark a message as clicked."""
    message = get_message(db, message_id)
    if not message:
        return None
    
    if not message.is_clicked:
        message.is_clicked = True
        message.clicked_at = datetime.utcnow()
        db.commit()
        db.refresh(message)
        
        # Create CLICKED event
        create_event(db, message_id, PhishingEventType.CLICKED, meta)
    
    return message


def mark_message_reported(db: Session, message_id: int, meta: dict = None) -> Optional[PhishingMessage]:
    """Mark a message as reported."""
    message = get_message(db, message_id)
    if not message:
        return None
    
    if not message.is_reported:
        message.is_reported = True
        message.reported_at = datetime.utcnow()
        db.commit()
        db.refresh(message)
        
        # Create REPORTED event
        create_event(db, message_id, PhishingEventType.REPORTED, meta)
    
    return message


# =============================================================================
# EVENT CRUD
# =============================================================================

def create_event(
    db: Session,
    message_id: int,
    event_type: PhishingEventType,
    ip_address: str = None,
    user_agent: str = None,
    hostname: str = None,
    meta: dict = None
) -> PhishingEvent:
    """Create a new event with tracking info."""
    event = PhishingEvent(
        message_id=message_id,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        hostname=hostname,
        meta_json=meta
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def get_events_by_message(db: Session, message_id: int) -> List[PhishingEvent]:
    """Get all events for a message."""
    return db.query(PhishingEvent).filter(
        PhishingEvent.message_id == message_id
    ).order_by(PhishingEvent.timestamp).all()


def get_events_by_campaign(db: Session, campaign_id: int) -> List[PhishingEvent]:
    """Get all events for a campaign."""
    return db.query(PhishingEvent).join(PhishingMessage).filter(
        PhishingMessage.campaign_id == campaign_id
    ).order_by(PhishingEvent.timestamp).all()


# =============================================================================
# METRICS / STATS
# =============================================================================

def get_campaign_stats(db: Session, campaign_id: int) -> Dict[str, Any]:
    """Get statistics for a campaign including full funnel metrics."""
    messages = get_messages_by_campaign(db, campaign_id)
    
    total = len(messages)
    sent = sum(1 for m in messages if m.status == "SENT")
    opened = sum(1 for m in messages if m.is_opened)
    clicked = sum(1 for m in messages if m.is_clicked)
    downloaded = sum(1 for m in messages if getattr(m, 'is_downloaded', False))
    executed = sum(1 for m in messages if getattr(m, 'is_executed', False))
    simulations = sum(1 for m in messages if getattr(m, 'simulation_run_id', None))
    reported = sum(1 for m in messages if m.is_reported)
    
    return {
        "total_messages": total,
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "downloaded": downloaded,
        "executed": executed,
        "simulations_triggered": simulations,
        "reported": reported,
        "open_rate": round((opened / sent * 100), 1) if sent > 0 else 0,
        "click_rate": round((clicked / sent * 100), 1) if sent > 0 else 0,
        "download_rate": round((downloaded / sent * 100), 1) if sent > 0 else 0,
        "execute_rate": round((executed / sent * 100), 1) if sent > 0 else 0,
        "report_rate": round((reported / sent * 100), 1) if sent > 0 else 0,
    }


def get_overall_stats(db: Session) -> Dict[str, Any]:
    """Get overall phishing simulation statistics."""
    campaigns = db.query(PhishingCampaign).all()
    messages = db.query(PhishingMessage).filter(PhishingMessage.status == "SENT").all()
    
    total_campaigns = len(campaigns)
    active_campaigns = sum(1 for c in campaigns if c.status == CampaignStatus.RUNNING)
    total_messages = len(messages)
    total_opened = sum(1 for m in messages if m.is_opened)
    total_clicked = sum(1 for m in messages if m.is_clicked)
    total_downloaded = sum(1 for m in messages if getattr(m, 'is_downloaded', False))
    total_executed = sum(1 for m in messages if getattr(m, 'is_executed', False))
    total_simulations = sum(1 for m in messages if getattr(m, 'simulation_run_id', None))
    total_reported = sum(1 for m in messages if m.is_reported)
    
    return {
        "total_campaigns": total_campaigns,
        "active_campaigns": active_campaigns,
        "total_messages": total_messages,
        "total_opened": total_opened,
        "total_clicked": total_clicked,
        "total_downloaded": total_downloaded,
        "total_executed": total_executed,
        "total_simulations": total_simulations,
        "total_reported": total_reported,
        "avg_open_rate": round((total_opened / total_messages * 100), 1) if total_messages > 0 else 0,
        "avg_click_rate": round((total_clicked / total_messages * 100), 1) if total_messages > 0 else 0,
        "avg_download_rate": round((total_downloaded / total_messages * 100), 1) if total_messages > 0 else 0,
        "avg_execute_rate": round((total_executed / total_messages * 100), 1) if total_messages > 0 else 0,
        "avg_report_rate": round((total_reported / total_messages * 100), 1) if total_messages > 0 else 0,
    }


# =============================================================================
# DOWNLOAD / EXECUTE TRACKING
# =============================================================================

def mark_message_downloaded(db: Session, message_id: int, meta: dict = None) -> Optional[PhishingMessage]:
    """Mark a message as downloaded (user downloaded launcher)."""
    message = get_message(db, message_id)
    if not message:
        return None
    
    if not getattr(message, 'is_downloaded', False):
        message.is_downloaded = True
        message.downloaded_at = datetime.utcnow()
        db.commit()
        db.refresh(message)
        
        # Create DOWNLOADED event
        create_event(
            db, message_id, PhishingEventType.DOWNLOADED,
            ip_address=meta.get('ip') if meta else None,
            user_agent=meta.get('user_agent') if meta else None,
            meta=meta
        )
    
    return message


def mark_message_executed(
    db: Session,
    message_id: int,
    hostname: str = None,
    simulation_run_id: int = None,
    meta: dict = None
) -> Optional[PhishingMessage]:
    """Mark a message as executed (user ran launcher)."""
    message = get_message(db, message_id)
    if not message:
        return None
    
    if not getattr(message, 'is_executed', False):
        message.is_executed = True
        message.executed_at = datetime.utcnow()
        if simulation_run_id:
            message.simulation_run_id = simulation_run_id
        db.commit()
        db.refresh(message)
        
        # Create EXECUTED event
        create_event(
            db, message_id, PhishingEventType.EXECUTED,
            ip_address=meta.get('ip') if meta else None,
            user_agent=meta.get('user_agent') if meta else None,
            hostname=hostname,
            meta=meta
        )
    
    return message


def mark_simulation_started(
    db: Session,
    message_id: int,
    run_id: int,
    meta: dict = None
) -> Optional[PhishingMessage]:
    """Mark that simulation was started from this phishing message."""
    message = get_message(db, message_id)
    if not message:
        return None
    
    message.simulation_run_id = run_id
    db.commit()
    db.refresh(message)
    
    # Create SIMULATION_STARTED event
    create_event(
        db, message_id, PhishingEventType.SIMULATION_STARTED,
        meta={"run_id": run_id, **(meta or {})}
    )
    
    return message


# =============================================================================
# TEMPLATE CRUD
# =============================================================================

def create_template(
    db: Session,
    name: str,
    key: str,
    subject: str,
    body_html: str,
    body_text: str = None,
    category: str = "general",
    description: str = None,
    variables: List[str] = None,
    has_attachment: bool = False,
    attachment_name: str = None,
    landing_page_type: str = "document",
    created_by: str = "admin"
) -> PhishingTemplate:
    """Create a new phishing template."""
    template = PhishingTemplate(
        name=name,
        key=key,
        subject=subject,
        body_html=body_html,
        body_text=body_text,
        category=category,
        description=description,
        variables=variables or [],
        has_attachment=has_attachment,
        attachment_name=attachment_name,
        landing_page_type=landing_page_type,
        created_by=created_by
    )
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


def get_template_by_id(db: Session, template_id: int) -> Optional[PhishingTemplate]:
    """Get a template by ID."""
    return db.query(PhishingTemplate).filter(PhishingTemplate.id == template_id).first()


def get_template_by_key(db: Session, key: str) -> Optional[PhishingTemplate]:
    """Get a template by key."""
    return db.query(PhishingTemplate).filter(PhishingTemplate.key == key).first()


def get_all_templates(db: Session, category: str = None, active_only: bool = True) -> List[PhishingTemplate]:
    """Get all templates, optionally filtered by category."""
    query = db.query(PhishingTemplate)
    if active_only:
        query = query.filter(PhishingTemplate.is_active == True)
    if category:
        query = query.filter(PhishingTemplate.category == category)
    return query.order_by(PhishingTemplate.category, PhishingTemplate.name).all()


def update_template(db: Session, template_id: int, **kwargs) -> Optional[PhishingTemplate]:
    """Update a template."""
    template = get_template_by_id(db, template_id)
    if not template:
        return None
    
    for key, value in kwargs.items():
        if hasattr(template, key):
            setattr(template, key, value)
    
    db.commit()
    db.refresh(template)
    return template


def delete_template(db: Session, template_id: int) -> bool:
    """Delete a template (soft delete by setting is_active=False)."""
    template = get_template_by_id(db, template_id)
    if not template:
        return False
    
    template.is_active = False
    db.commit()
    return True


# =============================================================================
# SETTINGS CRUD
# =============================================================================

def get_setting(db: Session, key: str) -> Optional[str]:
    """Get a setting value by key."""
    setting = db.query(PhishingSettings).filter(PhishingSettings.setting_key == key).first()
    return setting.setting_value if setting else None


def get_setting_typed(db: Session, key: str, default: Any = None) -> Any:
    """Get a setting value with type conversion."""
    setting = db.query(PhishingSettings).filter(PhishingSettings.setting_key == key).first()
    if not setting:
        return default
    
    value = setting.setting_value
    if setting.setting_type == "int":
        return int(value) if value else default
    elif setting.setting_type == "bool":
        return value.lower() in ("true", "1", "yes") if value else default
    elif setting.setting_type == "json":
        import json
        return json.loads(value) if value else default
    return value


def set_setting(
    db: Session,
    key: str,
    value: Any,
    setting_type: str = "string",
    description: str = None,
    updated_by: str = None
) -> PhishingSettings:
    """Set a setting value."""
    import json
    
    # Convert value to string for storage
    if setting_type == "json":
        str_value = json.dumps(value)
    elif setting_type == "bool":
        str_value = "true" if value else "false"
    else:
        str_value = str(value) if value is not None else None
    
    setting = db.query(PhishingSettings).filter(PhishingSettings.setting_key == key).first()
    if setting:
        setting.setting_value = str_value
        setting.setting_type = setting_type
        if description:
            setting.description = description
        setting.updated_by = updated_by
    else:
        setting = PhishingSettings(
            setting_key=key,
            setting_value=str_value,
            setting_type=setting_type,
            description=description,
            updated_by=updated_by
        )
        db.add(setting)
    
    db.commit()
    db.refresh(setting)
    return setting


def get_all_settings(db: Session) -> Dict[str, Any]:
    """Get all settings as a dictionary."""
    settings = db.query(PhishingSettings).all()
    result = {}
    for s in settings:
        result[s.setting_key] = get_setting_typed(db, s.setting_key)
    return result


def get_allowed_domains(db: Session) -> List[str]:
    """Get list of allowed email domains for phishing campaigns."""
    domains = get_setting_typed(db, "allowed_domains", [])
    if not domains:
        # Default domains for training
        return ["lab.local", "training.local", "example.local", "ransomrun.local"]
    return domains


def is_domain_allowed(db: Session, email: str) -> bool:
    """Check if an email domain is in the allowlist."""
    if not email or "@" not in email:
        return False
    domain = email.split("@")[1].lower()
    allowed = get_allowed_domains(db)
    return domain in [d.lower().strip() for d in allowed]


# =============================================================================
# SEED DEFAULT TEMPLATES
# =============================================================================

def seed_default_templates(db: Session) -> int:
    """Seed default phishing templates if none exist."""
    existing = db.query(PhishingTemplate).count()
    if existing > 0:
        return 0
    
    templates_data = [
        {
            "name": "IT Password Reset",
            "key": "it_password_reset",
            "category": "credential",
            "description": "IT department password reset notification",
            "subject": "[ACTION REQUIRED] Your Password Will Expire Soon",
            "body_html": """<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #0078d4; color: white; padding: 20px; text-align: center;">
<h2>IT Security Notice</h2>
</div>
<div style="padding: 20px; background: #f5f5f5;">
<p>Dear {{recipient_name}},</p>
<p>Your network password will expire in <strong>24 hours</strong>. To avoid disruption to your work, please update your password immediately.</p>
<p style="text-align: center; margin: 30px 0;">
<a href="{{tracking_link}}" style="background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password Now</a>
</p>
<p style="color: #666; font-size: 12px;">If you did not request this, please contact IT Support.</p>
<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
<p style="color: #999; font-size: 11px; text-align: center;">This is a security awareness training simulation.</p>
</div>
</div>""",
            "body_text": "Dear {{recipient_name}},\n\nYour network password will expire in 24 hours. Please click the link below to reset it:\n\n{{tracking_link}}\n\n[TRAINING SIMULATION]",
            "variables": ["recipient_name", "tracking_link"],
            "landing_page_type": "login"
        },
        {
            "name": "Invoice Attachment",
            "key": "invoice_attachment",
            "category": "attachment",
            "description": "Fake invoice with download link",
            "subject": "Invoice #{{invoice_number}} - Payment Required",
            "body_html": """<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="border-bottom: 3px solid #28a745; padding: 15px 0;">
<h2 style="margin: 0; color: #333;">Invoice Notification</h2>
</div>
<div style="padding: 20px;">
<p>Dear {{recipient_name}},</p>
<p>Please find attached your invoice <strong>#{{invoice_number}}</strong> for the amount of <strong>${{amount}}</strong>.</p>
<p>Payment is due within 30 days. Click below to view and download your invoice:</p>
<p style="text-align: center; margin: 30px 0;">
<a href="{{tracking_link}}" style="background: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">📄 View Invoice</a>
</p>
<p style="color: #666; font-size: 12px;">Questions? Reply to this email or call our billing department.</p>
<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
<p style="color: #999; font-size: 11px; text-align: center;">[SECURITY AWARENESS TRAINING]</p>
</div>
</div>""",
            "body_text": "Dear {{recipient_name}},\n\nInvoice #{{invoice_number}} for ${{amount}} is attached.\n\nDownload: {{tracking_link}}\n\n[TRAINING SIMULATION]",
            "variables": ["recipient_name", "tracking_link", "invoice_number", "amount"],
            "has_attachment": True,
            "attachment_name": "Invoice.pdf",
            "landing_page_type": "document"
        },
        {
            "name": "HR Policy Update",
            "key": "hr_policy_update",
            "category": "internal",
            "description": "HR department policy update notification",
            "subject": "Important: Updated Company Policy - Action Required",
            "body_html": """<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #6f42c1; color: white; padding: 20px;">
<h2 style="margin: 0;">Human Resources</h2>
<p style="margin: 5px 0 0 0; opacity: 0.9;">Policy Update Notice</p>
</div>
<div style="padding: 20px; background: #fafafa;">
<p>Dear {{recipient_name}},</p>
<p>We have updated our company policies effective immediately. All employees must review and acknowledge the new policies.</p>
<p><strong>Updated Policies:</strong></p>
<ul>
<li>Remote Work Guidelines</li>
<li>Data Security Requirements</li>
<li>Communication Standards</li>
</ul>
<p style="text-align: center; margin: 30px 0;">
<a href="{{tracking_link}}" style="background: #6f42c1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Review & Acknowledge</a>
</p>
<p style="color: #dc3545; font-size: 13px;"><strong>Deadline:</strong> Please complete by end of day Friday.</p>
<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
<p style="color: #999; font-size: 11px; text-align: center;">[PHISHING SIMULATION - Do not forward]</p>
</div>
</div>""",
            "body_text": "Dear {{recipient_name}},\n\nPlease review updated company policies: {{tracking_link}}\n\n[TRAINING SIMULATION]",
            "variables": ["recipient_name", "tracking_link"],
            "landing_page_type": "document"
        },
        {
            "name": "Package Delivery",
            "key": "package_delivery",
            "category": "external",
            "description": "Fake package delivery notification",
            "subject": "Your Package is Ready for Pickup - Tracking #{{tracking_number}}",
            "body_html": """<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<div style="background: #ff6600; color: white; padding: 20px; text-align: center;">
<h2 style="margin: 0;">📦 Delivery Notification</h2>
</div>
<div style="padding: 20px;">
<p>Hello {{recipient_name}},</p>
<p>Your package with tracking number <strong>{{tracking_number}}</strong> has arrived and is ready for pickup.</p>
<p>Please confirm your delivery details to schedule final delivery:</p>
<p style="text-align: center; margin: 30px 0;">
<a href="{{tracking_link}}" style="background: #ff6600; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Confirm Delivery</a>
</p>
<p style="color: #666; font-size: 12px;">Package will be returned to sender if not claimed within 5 days.</p>
<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
<p style="color: #999; font-size: 11px; text-align: center;">[SECURITY TRAINING EXERCISE]</p>
</div>
</div>""",
            "body_text": "Hello {{recipient_name}},\n\nYour package #{{tracking_number}} is ready. Confirm: {{tracking_link}}\n\n[TRAINING]",
            "variables": ["recipient_name", "tracking_link", "tracking_number"],
            "landing_page_type": "login"
        }
    ]
    
    created = 0
    for t in templates_data:
        template = PhishingTemplate(
            name=t["name"],
            key=t["key"],
            category=t["category"],
            description=t["description"],
            subject=t["subject"],
            body_html=t["body_html"],
            body_text=t["body_text"],
            variables=t["variables"],
            has_attachment=t.get("has_attachment", False),
            attachment_name=t.get("attachment_name"),
            landing_page_type=t.get("landing_page_type", "document"),
            created_by="system"
        )
        db.add(template)
        created += 1
    
    db.commit()
    return created


def seed_default_settings(db: Session) -> int:
    """Seed default phishing settings if none exist."""
    defaults = [
        ("allowed_domains", '["lab.local", "training.local", "example.local", "ransomrun.local"]', "json", "Allowed email domains for recipients"),
        ("smtp_enabled", "false", "bool", "Enable SMTP email delivery"),
        ("smtp_host", "", "string", "SMTP server hostname"),
        ("smtp_port", "587", "int", "SMTP server port"),
        ("smtp_username", "", "string", "SMTP username"),
        ("smtp_password", "", "string", "SMTP password (encrypted)"),
        ("smtp_use_tls", "true", "bool", "Use TLS for SMTP"),
        ("smtp_from_email", "training@ransomrun.local", "string", "From email address"),
        ("smtp_from_name", "Security Training", "string", "From display name"),
        ("token_expiry_days", "7", "int", "Days until tracking tokens expire"),
        ("rate_limit_per_minute", "10", "int", "Max tracking requests per minute per IP"),
        ("launcher_filename", "SecurityTraining.exe", "string", "Name of launcher file"),
        ("base_url", "http://localhost:8000", "string", "Base URL for tracking links"),
    ]
    
    created = 0
    for key, value, stype, desc in defaults:
        existing = db.query(PhishingSettings).filter(PhishingSettings.setting_key == key).first()
        if not existing:
            setting = PhishingSettings(
                setting_key=key,
                setting_value=value,
                setting_type=stype,
                description=desc,
                updated_by="system"
            )
            db.add(setting)
            created += 1
    
    db.commit()
    return created
