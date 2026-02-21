"""
Phishing Awareness Simulator - Safe Training Templates
=======================================================
Provides neutral, clearly-labeled training email templates.

SAFETY REQUIREMENTS:
- All templates include [SIMULATION] banner
- No urgency/threat/authority pressure tactics
- No requests for passwords or MFA codes
- All links resolve to internal routes only
- No deceptive attachments
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class PhishingTemplate:
    """A safe phishing training template."""
    key: str
    name: str
    category: str
    description: str
    subject: str
    body_html: str
    body_text: str
    has_attachment: bool = False
    attachment_name: Optional[str] = None


# =============================================================================
# SAFE TRAINING TEMPLATES
# =============================================================================

PHISHING_TEMPLATES: Dict[str, PhishingTemplate] = {
    
    # -------------------------------------------------------------------------
    # PASSWORD RESET SIMULATIONS
    # -------------------------------------------------------------------------
    
    "password_reset_it": PhishingTemplate(
        key="password_reset_it",
        name="IT Password Reset Notice",
        category="Password Reset",
        description="IT department password reset notification.",
        subject="Action Required: Password Expiration Notice",
        body_html="""
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; background: #ffffff;">
    <div style="background: #0078d4; padding: 20px; text-align: center;">
        <h1 style="color: white; margin: 0; font-size: 22px;">IT Security Services</h1>
    </div>
    
    <div style="padding: 30px;">
        <p style="color: #333333; font-size: 15px;">Dear {recipient_name},</p>
        
        <p style="color: #333333; font-size: 15px;">Our security system has detected that your password will expire in <strong>24 hours</strong>. To maintain uninterrupted access to company resources, please update your password immediately.</p>
        
        <div style="background: #fff4e5; border-left: 4px solid #ff9800; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #333333; font-size: 14px;"><strong>Important:</strong> Failure to update your password may result in account lockout and loss of access to email, VPN, and internal systems.</p>
        </div>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_link}" style="background: #0078d4; color: white; padding: 14px 40px; text-decoration: none; border-radius: 4px; font-weight: 600; display: inline-block;">Update Password Now</a>
        </p>
        
        <p style="color: #666666; font-size: 14px;">If you have recently updated your password, please disregard this message.</p>
        
        <p style="color: #333333; font-size: 15px; margin-top: 25px;">Best regards,<br><strong>IT Security Team</strong></p>
    </div>
    
    <div style="background: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #888888;">
        <p style="margin: 0;">This is an automated message from IT Security Services.</p>
        <p style="margin: 5px 0 0 0;">Please do not reply to this email.</p>
    </div>
</div>
""",
        body_text="""
IT Security Services

Dear {recipient_name},

Our security system has detected that your password will expire in 24 hours. To maintain uninterrupted access to company resources, please update your password immediately.

IMPORTANT: Failure to update your password may result in account lockout and loss of access to email, VPN, and internal systems.

Update Password Now: {tracking_link}

If you have recently updated your password, please disregard this message.

Best regards,
IT Security Team

This is an automated message from IT Security Services.
Please do not reply to this email.
"""
    ),
    
    # -------------------------------------------------------------------------
    # INVOICE SIMULATIONS
    # -------------------------------------------------------------------------
    
    "invoice_pending": PhishingTemplate(
        key="invoice_pending",
        name="Pending Invoice Notification",
        category="Invoice",
        description="Pending invoice notification from accounting.",
        subject="Invoice #INV-2024-{random_id} - Payment Required",
        body_html="""
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #1a365d; padding: 20px;">
        <h1 style="color: white; margin: 0; font-size: 20px;">Finance Department</h1>
    </div>
    
    <div style="padding: 30px;">
        <p style="color: #333333;">Hello {recipient_name},</p>
        
        <p style="color: #333333;">You have a pending invoice that requires your immediate review and approval. Please process this invoice before the due date to avoid late payment fees.</p>
        
        <table style="width: 100%; margin: 25px 0; border-collapse: collapse; border: 1px solid #e2e8f0;">
            <tr style="background: #f7fafc;">
                <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0; font-weight: 600; color: #4a5568;">Invoice Number</td>
                <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0; color: #2d3748;">INV-2024-{random_id}</td>
            </tr>
            <tr>
                <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0; font-weight: 600; color: #4a5568;">Amount Due</td>
                <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0; color: #c53030; font-weight: bold;">$3,847.50</td>
            </tr>
            <tr style="background: #f7fafc;">
                <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0; font-weight: 600; color: #4a5568;">Due Date</td>
                <td style="padding: 12px 15px; border-bottom: 1px solid #e2e8f0; color: #2d3748;">{due_date}</td>
            </tr>
            <tr>
                <td style="padding: 12px 15px; font-weight: 600; color: #4a5568;">Vendor</td>
                <td style="padding: 12px 15px; color: #2d3748;">Global Business Solutions Ltd.</td>
            </tr>
        </table>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_link}" style="background: #2b6cb0; color: white; padding: 14px 35px; text-decoration: none; border-radius: 5px; font-weight: 600; display: inline-block;">View & Approve Invoice</a>
        </p>
        
        <p style="color: #718096; font-size: 14px;">If you have any questions regarding this invoice, please contact the Finance department.</p>
        
        <p style="color: #333333; margin-top: 25px;">Best regards,<br><strong>Accounts Payable Team</strong><br>Finance Department</p>
    </div>
    
    <div style="background: #f7fafc; padding: 15px; text-align: center; font-size: 11px; color: #a0aec0; border-top: 1px solid #e2e8f0;">
        <p style="margin: 0;">This is an automated notification from the Finance Department.</p>
    </div>
</div>
""",
        body_text="""
Finance Department

Hello {recipient_name},

You have a pending invoice that requires your immediate review and approval. Please process this invoice before the due date to avoid late payment fees.

Invoice Number: INV-2024-{random_id}
Amount Due: $3,847.50
Due Date: {due_date}
Vendor: Global Business Solutions Ltd.

View & Approve Invoice: {tracking_link}

If you have any questions regarding this invoice, please contact the Finance department.

Best regards,
Accounts Payable Team
Finance Department
"""
    ),
    
    # -------------------------------------------------------------------------
    # SHARED DOCUMENT SIMULATIONS
    # -------------------------------------------------------------------------
    
    "shared_document": PhishingTemplate(
        key="shared_document",
        name="Shared Document Notification",
        category="Shared Document",
        description="Microsoft OneDrive document sharing notification.",
        subject="{sender_name} shared 'Q4 Financial Report.xlsx' with you",
        body_html="""
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #0078d4; padding: 15px 20px;">
        <table style="width: 100%;">
            <tr>
                <td><span style="color: white; font-size: 18px; font-weight: 600;">OneDrive</span></td>
            </tr>
        </table>
    </div>
    
    <div style="padding: 30px;">
        <div style="text-align: center; margin-bottom: 25px;">
            <div style="width: 70px; height: 70px; background: linear-gradient(135deg, #0078d4, #00bcf2); border-radius: 8px; margin: 0 auto; display: flex; align-items: center; justify-content: center;">
                <span style="color: white; font-size: 32px;">📄</span>
            </div>
        </div>
        
        <h2 style="color: #252423; text-align: center; margin: 0 0 20px 0; font-size: 20px; font-weight: 600;">{sender_name} shared a file with you</h2>
        
        <div style="background: #f3f2f1; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="width: 40px; vertical-align: top;">
                        <span style="font-size: 28px;">📊</span>
                    </td>
                    <td>
                        <p style="margin: 0; font-weight: 600; color: #252423;">Q4 Financial Report.xlsx</p>
                        <p style="margin: 5px 0 0 0; font-size: 13px; color: #605e5c;">Excel Workbook • 2.4 MB</p>
                    </td>
                </tr>
            </table>
        </div>
        
        <p style="text-align: center; margin: 25px 0;">
            <a href="{tracking_link}" style="background: #0078d4; color: white; padding: 12px 40px; text-decoration: none; border-radius: 4px; font-weight: 600; display: inline-block;">Open</a>
        </p>
        
        <p style="color: #605e5c; font-size: 13px; text-align: center;">This link will work for anyone.</p>
    </div>
    
    <div style="background: #faf9f8; padding: 20px; border-top: 1px solid #edebe9;">
        <p style="margin: 0; font-size: 12px; color: #605e5c; text-align: center;">Microsoft respects your privacy. To learn more, please read our Privacy Statement.</p>
    </div>
</div>
""",
        body_text="""
OneDrive

{sender_name} shared a file with you

Q4 Financial Report.xlsx
Excel Workbook - 2.4 MB

Open: {tracking_link}

This link will work for anyone.

Microsoft respects your privacy.
"""
    ),
    
    # -------------------------------------------------------------------------
    # DELIVERY NOTIFICATION SIMULATIONS
    # -------------------------------------------------------------------------
    
    "package_delivery": PhishingTemplate(
        key="package_delivery",
        name="Package Delivery Notification",
        category="Delivery",
        description="DHL Express delivery notification.",
        subject="DHL Express: Delivery scheduled for today - Action required",
        body_html="""
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #d40511; padding: 20px; text-align: center;">
        <h1 style="color: #ffcc00; margin: 0; font-size: 28px; font-weight: bold;">DHL</h1>
    </div>
    
    <div style="padding: 30px;">
        <h2 style="color: #333333; margin-top: 0;">Your shipment is on its way</h2>
        <p style="color: #333333;">Hello {recipient_name},</p>
        <p style="color: #333333;">Great news! Your package is scheduled for delivery today. Please confirm your delivery preferences to ensure successful delivery.</p>
        
        <div style="background: #f5f5f5; padding: 20px; border-radius: 4px; margin: 25px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Tracking Number:</td>
                    <td style="padding: 8px 0; color: #333333; font-weight: bold;">DHL-{random_id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Status:</td>
                    <td style="padding: 8px 0; color: #d40511; font-weight: bold;">Out for Delivery</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Expected:</td>
                    <td style="padding: 8px 0; color: #333333;">Today by 6:00 PM</td>
                </tr>
            </table>
        </div>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_link}" style="background: #d40511; color: white; padding: 14px 40px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Confirm Delivery</a>
        </p>
        
        <p style="color: #666666; font-size: 14px;">If you will not be available, please reschedule your delivery using the link above.</p>
    </div>
    
    <div style="background: #333333; padding: 20px; text-align: center;">
        <p style="color: #999999; font-size: 12px; margin: 0;">DHL Express - Excellence. Simply delivered.</p>
    </div>
</div>
""",
        body_text="""
DHL Express

Your shipment is on its way

Hello {recipient_name},

Great news! Your package is scheduled for delivery today. Please confirm your delivery preferences to ensure successful delivery.

Tracking Number: DHL-{random_id}
Status: Out for Delivery
Expected: Today by 6:00 PM

Confirm Delivery: {tracking_link}

If you will not be available, please reschedule your delivery using the link above.

DHL Express - Excellence. Simply delivered.
"""
    ),
    
    # -------------------------------------------------------------------------
    # HR SIMULATIONS
    # -------------------------------------------------------------------------
    
    "hr_policy_update": PhishingTemplate(
        key="hr_policy_update",
        name="HR Policy Update",
        category="HR",
        description="HR policy update requiring acknowledgment.",
        subject="Important: Updated Company Policy - Acknowledgment Required by Friday",
        body_html="""
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #2c3e50; padding: 25px;">
        <h1 style="color: white; margin: 0; font-size: 22px;">Human Resources</h1>
        <p style="color: #bdc3c7; margin: 5px 0 0 0; font-size: 14px;">Policy & Compliance</p>
    </div>
    
    <div style="padding: 30px;">
        <p style="color: #333333;">Dear {recipient_name},</p>
        
        <p style="color: #333333;">As part of our ongoing commitment to maintaining a secure and compliant workplace, we have updated several company policies effective immediately.</p>
        
        <div style="background: #ecf0f1; padding: 20px; border-radius: 6px; margin: 25px 0;">
            <p style="margin: 0 0 15px 0; color: #2c3e50; font-weight: 600;">Policy Updates Include:</p>
            <ul style="margin: 0; padding-left: 20px; color: #555555;">
                <li style="margin-bottom: 8px;">Remote Work & Hybrid Schedule Guidelines</li>
                <li style="margin-bottom: 8px;">Data Protection & Privacy Requirements</li>
                <li style="margin-bottom: 8px;">Information Security Protocols</li>
                <li style="margin-bottom: 8px;">Acceptable Use Policy Updates</li>
            </ul>
        </div>
        
        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #856404;"><strong>Action Required:</strong> All employees must review and acknowledge these policy changes by end of business Friday.</p>
        </div>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_link}" style="background: #3498db; color: white; padding: 14px 40px; text-decoration: none; border-radius: 5px; font-weight: 600; display: inline-block;">Review & Acknowledge Policies</a>
        </p>
        
        <p style="color: #333333; margin-top: 25px;">Thank you for your prompt attention to this matter.</p>
        
        <p style="color: #333333;">Best regards,<br><strong>Human Resources Department</strong><br>Policy & Compliance Team</p>
    </div>
    
    <div style="background: #f8f9fa; padding: 15px; text-align: center; font-size: 11px; color: #6c757d; border-top: 1px solid #dee2e6;">
        <p style="margin: 0;">This is an official communication from Human Resources.</p>
    </div>
</div>
""",
        body_text="""
Human Resources - Policy & Compliance

Dear {recipient_name},

As part of our ongoing commitment to maintaining a secure and compliant workplace, we have updated several company policies effective immediately.

Policy Updates Include:
- Remote Work & Hybrid Schedule Guidelines
- Data Protection & Privacy Requirements
- Information Security Protocols
- Acceptable Use Policy Updates

ACTION REQUIRED: All employees must review and acknowledge these policy changes by end of business Friday.

Review & Acknowledge Policies: {tracking_link}

Thank you for your prompt attention to this matter.

Best regards,
Human Resources Department
Policy & Compliance Team
"""
    ),
    
    # -------------------------------------------------------------------------
    # MEETING SIMULATIONS
    # -------------------------------------------------------------------------
    
    "meeting_invite": PhishingTemplate(
        key="meeting_invite",
        name="Meeting Invitation",
        category="Meeting",
        description="Microsoft Teams meeting invitation.",
        subject="{sender_name} invited you to: Urgent Budget Review Meeting",
        body_html="""
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #464775; padding: 15px 20px;">
        <span style="color: white; font-size: 18px; font-weight: 600;">Microsoft Teams</span>
    </div>
    
    <div style="padding: 25px;">
        <p style="color: #242424; font-size: 14px; margin: 0 0 20px 0;">{sender_name} invited you to a meeting</p>
        
        <h2 style="color: #242424; margin: 0 0 20px 0; font-size: 22px;">Urgent Budget Review Meeting</h2>
        
        <div style="border-left: 3px solid #464775; padding-left: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px 0; color: #616161; font-size: 14px;">{meeting_date}</p>
            <p style="margin: 0 0 8px 0; color: #616161; font-size: 14px;">2:00 PM - 3:00 PM (GMT+4)</p>
            <p style="margin: 0; color: #616161; font-size: 14px;">Microsoft Teams Meeting</p>
        </div>
        
        <p style="text-align: left; margin: 25px 0;">
            <a href="{tracking_link}" style="background: #464775; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; font-size: 14px; display: inline-block; margin-right: 10px;">Accept</a>
            <a href="{tracking_link}" style="background: #ffffff; color: #464775; padding: 10px 20px; text-decoration: none; border-radius: 3px; font-size: 14px; display: inline-block; border: 1px solid #464775;">Tentative</a>
            <a href="{tracking_link}" style="background: #ffffff; color: #464775; padding: 10px 20px; text-decoration: none; border-radius: 3px; font-size: 14px; display: inline-block; border: 1px solid #464775; margin-left: 10px;">Decline</a>
        </p>
        
        <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin-top: 20px;">
            <p style="margin: 0; color: #616161; font-size: 13px;"><strong>Join on your computer or mobile app</strong></p>
            <p style="margin: 8px 0 0 0;"><a href="{tracking_link}" style="color: #6264a7; text-decoration: none;">Click here to join the meeting</a></p>
        </div>
    </div>
    
    <div style="background: #f5f5f5; padding: 15px; text-align: center; font-size: 11px; color: #616161;">
        <p style="margin: 0;">Microsoft Teams | Microsoft Corporation</p>
    </div>
</div>
""",
        body_text="""
Microsoft Teams

{sender_name} invited you to a meeting

Urgent Budget Review Meeting

{meeting_date}
2:00 PM - 3:00 PM (GMT+4)
Microsoft Teams Meeting

Accept | Tentative | Decline

Join on your computer or mobile app:
{tracking_link}

Microsoft Teams | Microsoft Corporation
"""
    ),
    
    # -------------------------------------------------------------------------
    # SECURITY ALERT SIMULATIONS
    # -------------------------------------------------------------------------
    
    "security_alert": PhishingTemplate(
        key="security_alert",
        name="Security Alert",
        category="Security",
        description="Microsoft account security alert.",
        subject="Microsoft account security alert - Unusual sign-in activity",
        body_html="""
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #0078d4; padding: 20px;">
        <span style="color: white; font-size: 20px; font-weight: 600;">Microsoft</span>
    </div>
    
    <div style="padding: 30px;">
        <h2 style="color: #d83b01; margin: 0 0 20px 0; font-size: 20px;">Unusual sign-in activity</h2>
        
        <p style="color: #333333;">Hi {recipient_name},</p>
        
        <p style="color: #333333;">We detected something unusual about a recent sign-in to your Microsoft account.</p>
        
        <div style="background: #f3f3f3; padding: 20px; margin: 25px 0; border-radius: 4px;">
            <table style="width: 100%;">
                <tr>
                    <td style="padding: 8px 0; color: #666666; width: 120px;">Country/region:</td>
                    <td style="padding: 8px 0; color: #333333;">Russia</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">IP address:</td>
                    <td style="padding: 8px 0; color: #333333;">185.220.101.{random_id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Date:</td>
                    <td style="padding: 8px 0; color: #333333;">{timestamp}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Platform:</td>
                    <td style="padding: 8px 0; color: #333333;">Windows 10</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Browser:</td>
                    <td style="padding: 8px 0; color: #333333;">Chrome</td>
                </tr>
            </table>
        </div>
        
        <p style="color: #333333;">If this was you, you can ignore this message. If you didn't sign in recently, your account may be compromised. Please secure your account immediately.</p>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_link}" style="background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; display: inline-block;">Review recent activity</a>
        </p>
        
        <p style="color: #666666; font-size: 13px;">Thanks,<br>The Microsoft account team</p>
    </div>
    
    <div style="background: #f3f3f3; padding: 15px; text-align: center; font-size: 11px; color: #666666;">
        <p style="margin: 0;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
    </div>
</div>
""",
        body_text="""
Microsoft

Unusual sign-in activity

Hi {recipient_name},

We detected something unusual about a recent sign-in to your Microsoft account.

Country/region: Russia
IP address: 185.220.101.{random_id}
Date: {timestamp}
Platform: Windows 10
Browser: Chrome

If this was you, you can ignore this message. If you didn't sign in recently, your account may be compromised. Please secure your account immediately.

Review recent activity: {tracking_link}

Thanks,
The Microsoft account team

Microsoft Corporation, One Microsoft Way, Redmond, WA 98052
"""
    ),
    
    # -------------------------------------------------------------------------
    # VOICEMAIL SIMULATIONS
    # -------------------------------------------------------------------------
    
    "voicemail_notification": PhishingTemplate(
        key="voicemail_notification",
        name="Voicemail Notification",
        category="Voicemail",
        description="Office 365 voicemail notification.",
        subject="You have a new voicemail from +1 (555) 847-{random_id}",
        body_html="""
<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #0078d4; padding: 15px 20px;">
        <span style="color: white; font-size: 18px;">Microsoft 365</span>
    </div>
    
    <div style="padding: 30px;">
        <h2 style="color: #333333; margin: 0 0 20px 0;">You received a voicemail</h2>
        
        <div style="background: #f5f5f5; padding: 20px; border-radius: 4px; margin: 20px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="padding: 8px 0; color: #666666; width: 100px;">From:</td>
                    <td style="padding: 8px 0; color: #333333;">+1 (555) 847-{random_id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Duration:</td>
                    <td style="padding: 8px 0; color: #333333;">00:47</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666666;">Received:</td>
                    <td style="padding: 8px 0; color: #333333;">{timestamp}</td>
                </tr>
            </table>
        </div>
        
        <div style="background: #fff4ce; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <p style="margin: 0; color: #333333; font-size: 14px;"><strong>Transcription preview:</strong></p>
            <p style="margin: 10px 0 0 0; color: #666666; font-style: italic;">"Hi, this is regarding your account. Please call us back as soon as possible regarding an urgent matter..."</p>
        </div>
        
        <p style="text-align: center; margin: 25px 0;">
            <a href="{tracking_link}" style="background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: 600; display: inline-block;">▶ Play Voicemail</a>
        </p>
    </div>
    
    <div style="background: #f5f5f5; padding: 15px; text-align: center; font-size: 11px; color: #666666;">
        <p style="margin: 0;">Microsoft 365 | Voicemail Service</p>
    </div>
</div>
""",
        body_text="""
Microsoft 365

You received a voicemail

From: +1 (555) 847-{random_id}
Duration: 00:47
Received: {timestamp}

Transcription preview:
"Hi, this is regarding your account. Please call us back as soon as possible regarding an urgent matter..."

Play Voicemail: {tracking_link}

Microsoft 365 | Voicemail Service
"""
    ),
    
    # -------------------------------------------------------------------------
    # SOFTWARE UPDATE SIMULATIONS
    # -------------------------------------------------------------------------
    
    "software_update": PhishingTemplate(
        key="software_update",
        name="Software Update Required",
        category="Software",
        description="Adobe Acrobat update notification.",
        subject="Adobe Acrobat DC - Critical Security Update Required",
        body_html="""
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #ffffff;">
    <div style="background: #fa0f00; padding: 20px;">
        <span style="color: white; font-size: 22px; font-weight: bold;">Adobe</span>
    </div>
    
    <div style="padding: 30px;">
        <h2 style="color: #333333; margin: 0 0 20px 0;">Critical Security Update Available</h2>
        
        <p style="color: #333333;">Hello {recipient_name},</p>
        
        <p style="color: #333333;">A critical security update is available for Adobe Acrobat DC installed on your computer. This update addresses important security vulnerabilities and is strongly recommended.</p>
        
        <div style="background: #fff0f0; border-left: 4px solid #fa0f00; padding: 15px; margin: 25px 0;">
            <p style="margin: 0; color: #333333;"><strong>Security Advisory:</strong> CVE-2024-{random_id}</p>
            <p style="margin: 10px 0 0 0; color: #666666; font-size: 14px;">This vulnerability could allow remote code execution. Update immediately.</p>
        </div>
        
        <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
            <table style="width: 100%;">
                <tr>
                    <td style="padding: 5px 0; color: #666666;">Product:</td>
                    <td style="padding: 5px 0; color: #333333;">Adobe Acrobat DC 2024</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #666666;">Update Version:</td>
                    <td style="padding: 5px 0; color: #333333;">24.001.20604</td>
                </tr>
                <tr>
                    <td style="padding: 5px 0; color: #666666;">Priority:</td>
                    <td style="padding: 5px 0; color: #fa0f00; font-weight: bold;">Critical</td>
                </tr>
            </table>
        </div>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{tracking_link}" style="background: #fa0f00; color: white; padding: 14px 40px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Download Update Now</a>
        </p>
        
        <p style="color: #666666; font-size: 13px;">Adobe Systems Incorporated</p>
    </div>
    
    <div style="background: #333333; padding: 15px; text-align: center; font-size: 11px; color: #999999;">
        <p style="margin: 0;">Adobe, the Adobe logo, and Acrobat are trademarks of Adobe Inc.</p>
    </div>
</div>
""",
        body_text="""
Adobe

Critical Security Update Available

Hello {recipient_name},

A critical security update is available for Adobe Acrobat DC installed on your computer. This update addresses important security vulnerabilities and is strongly recommended.

Security Advisory: CVE-2024-{random_id}
This vulnerability could allow remote code execution. Update immediately.

Product: Adobe Acrobat DC 2024
Update Version: 24.001.20604
Priority: Critical

Download Update Now: {tracking_link}

Adobe Systems Incorporated
"""
    ),
    
    # -------------------------------------------------------------------------
    # SURVEY SIMULATIONS
    # -------------------------------------------------------------------------
    
    "employee_survey": PhishingTemplate(
        key="employee_survey",
        name="Employee Survey",
        category="Survey",
        description="Employee satisfaction survey request.",
        subject="Your Feedback Matters - Employee Survey",
        body_html="""
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <div style="border-bottom: 3px solid #4f46e5; padding-bottom: 15px; margin-bottom: 20px;">
        <h1 style="color: #1f2937; margin: 0; font-size: 24px;">Human Resources</h1>
        <p style="color: #6b7280; margin: 5px 0 0 0; font-size: 14px;">Employee Engagement Team</p>
    </div>
    
    <p style="color: #374151;">Dear {recipient_name},</p>
    
    <p style="color: #374151;">We value your feedback! Please take a few minutes to complete our annual employee satisfaction survey.</p>
    
    <p style="color: #374151;">Your responses are <strong>completely anonymous</strong> and will help us improve the workplace environment for everyone.</p>
    
    <div style="background: #f9fafb; padding: 20px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #4f46e5;">
        <p style="margin: 0 0 10px 0; color: #374151;"><strong>Survey Details:</strong></p>
        <ul style="margin: 0; padding-left: 20px; color: #6b7280;">
            <li>Estimated time: 5 minutes</li>
            <li>Deadline: End of this week</li>
            <li>All responses are confidential</li>
        </ul>
    </div>
    
    <p style="text-align: center; margin: 30px 0;">
        <a href="{tracking_link}" style="background: #4f46e5; color: white; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
            Complete Survey Now
        </a>
    </p>
    
    <p style="color: #374151;">Your participation helps us create a better workplace for everyone.</p>
    
    <p style="color: #374151; margin-top: 25px;">Best regards,<br><strong>HR Department</strong><br>Employee Engagement Team</p>
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af;">
        <p style="margin: 0;">This email was sent to {recipient_name}. If you believe you received this in error, please contact HR.</p>
    </div>
</div>
""",
        body_text="""
Human Resources - Employee Engagement Team

Dear {recipient_name},

We value your feedback! Please take a few minutes to complete our annual employee satisfaction survey.

Your responses are completely anonymous and will help us improve the workplace environment for everyone.

Survey Details:
- Estimated time: 5 minutes
- Deadline: End of this week
- All responses are confidential

Complete Survey Now: {tracking_link}

Your participation helps us create a better workplace for everyone.

Best regards,
HR Department
Employee Engagement Team
"""
    ),
    
    # -------------------------------------------------------------------------
    # ATTACHMENT SIMULATION (Safe placeholder)
    # -------------------------------------------------------------------------
    
    "document_attachment": PhishingTemplate(
        key="document_attachment",
        name="Document with Attachment",
        category="Attachment",
        description="Simulates an email with a safe attachment placeholder.",
        subject="[SIMULATION] Document for Review - {sender_name}",
        body_html="""
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #fef3c7; border: 1px solid #f59e0b; padding: 12px; margin-bottom: 20px; border-radius: 4px;">
        <strong>⚠️ [SIMULATION]</strong> This is a phishing awareness training message.
    </div>
    
    <div style="background: #f3f4f6; padding: 20px; border-radius: 8px;">
        <p>Hi {recipient_name},</p>
        <p>Please find the attached document for your review.</p>
        <p>Let me know if you have any questions.</p>
        
        <div style="background: white; padding: 12px; border-radius: 4px; margin: 20px 0; border: 1px solid #e5e7eb;">
            <a href="{tracking_link}" style="display: flex; align-items: center; text-decoration: none; color: #1f2937;">
                <span style="font-size: 24px; margin-right: 12px;">📎</span>
                <div>
                    <strong>Report_Q4_2024.pdf</strong>
                    <p style="margin: 0; font-size: 12px; color: #6b7280;">PDF Document - 245 KB</p>
                </div>
            </a>
        </div>
        
        <p>Best regards,<br>{sender_name}</p>
    </div>
    
    <div style="margin-top: 20px; padding: 12px; background: #dbeafe; border-radius: 4px; font-size: 12px;">
        This is a training exercise. Never open unexpected attachments without verification.
    </div>
</div>
""",
        body_text="""
[SIMULATION] This is a phishing awareness training message.

Hi {recipient_name},

Please find the attached document for your review.

Let me know if you have any questions.

📎 Attachment: Report_Q4_2024.pdf (245 KB)
Download: {tracking_link}

Best regards,
{sender_name}

---
This is a training exercise. Never open unexpected attachments without verification.
""",
        has_attachment=True,
        attachment_name="Report_Q4_2024.pdf"
    ),
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_all_templates() -> List[PhishingTemplate]:
    """Returns all available phishing templates."""
    return list(PHISHING_TEMPLATES.values())


def get_template(key: str) -> Optional[PhishingTemplate]:
    """Get a specific template by key."""
    return PHISHING_TEMPLATES.get(key)


def get_templates_by_category(category: str) -> List[PhishingTemplate]:
    """Get all templates in a category."""
    return [t for t in PHISHING_TEMPLATES.values() if t.category == category]


def get_template_categories() -> List[str]:
    """Get list of unique categories."""
    return list(set(t.category for t in PHISHING_TEMPLATES.values()))


def render_template(
    template: PhishingTemplate,
    recipient_name: str,
    tracking_link: str,
    sender_name: str = "John Smith",
    **kwargs
) -> Dict[str, str]:
    """
    Render a template with variables replaced.
    
    Returns dict with 'subject', 'body_html', 'body_text'.
    """
    import random
    from datetime import datetime, timedelta
    
    # Generate random values
    random_id = str(random.randint(100000, 999999))
    due_date = (datetime.now() + timedelta(days=7)).strftime("%B %d, %Y")
    meeting_date = (datetime.now() + timedelta(days=3)).strftime("%A, %B %d, %Y")
    timestamp = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    
    # Build replacement dict
    replacements = {
        "{recipient_name}": recipient_name,
        "{tracking_link}": tracking_link,
        "{sender_name}": sender_name,
        "{random_id}": random_id,
        "{due_date}": due_date,
        "{meeting_date}": meeting_date,
        "{timestamp}": timestamp,
    }
    replacements.update({f"{{{k}}}": v for k, v in kwargs.items()})
    
    # Replace in all fields
    subject = template.subject
    body_html = template.body_html
    body_text = template.body_text
    
    for placeholder, value in replacements.items():
        subject = subject.replace(placeholder, str(value))
        body_html = body_html.replace(placeholder, str(value))
        body_text = body_text.replace(placeholder, str(value))
    
    return {
        "subject": subject,
        "body_html": body_html,
        "body_text": body_text
    }
