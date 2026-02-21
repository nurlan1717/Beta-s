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
    meta: dict = None
) -> PhishingEvent:
    """Create a new event."""
    event = PhishingEvent(
        message_id=message_id,
        event_type=event_type,
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
    """Get statistics for a campaign."""
    messages = get_messages_by_campaign(db, campaign_id)
    
    total = len(messages)
    sent = sum(1 for m in messages if m.status == "SENT")
    opened = sum(1 for m in messages if m.is_opened)
    clicked = sum(1 for m in messages if m.is_clicked)
    reported = sum(1 for m in messages if m.is_reported)
    
    return {
        "total_messages": total,
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "reported": reported,
        "open_rate": (opened / sent * 100) if sent > 0 else 0,
        "click_rate": (clicked / sent * 100) if sent > 0 else 0,
        "report_rate": (reported / sent * 100) if sent > 0 else 0,
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
    total_reported = sum(1 for m in messages if m.is_reported)
    
    return {
        "total_campaigns": total_campaigns,
        "active_campaigns": active_campaigns,
        "total_messages": total_messages,
        "total_opened": total_opened,
        "total_clicked": total_clicked,
        "total_reported": total_reported,
        "avg_open_rate": (total_opened / total_messages * 100) if total_messages > 0 else 0,
        "avg_click_rate": (total_clicked / total_messages * 100) if total_messages > 0 else 0,
        "avg_report_rate": (total_reported / total_messages * 100) if total_messages > 0 else 0,
    }
