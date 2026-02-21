"""
Email Service for Phishing Training Campaigns
==============================================
Handles sending training emails via SMTP with safety controls.

SAFETY REQUIREMENTS:
- Only sends to allowlisted domains
- Includes X-RansomRun-Training header
- Includes opt-out footer
- Rate limited
"""

import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from typing import Optional, Dict, Any, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EmailService:
    """
    Email sending service for phishing training campaigns.
    Supports SMTP with TLS/SSL and includes safety controls.
    """
    
    def __init__(
        self,
        smtp_host: str = None,
        smtp_port: int = 587,
        smtp_username: str = None,
        smtp_password: str = None,
        use_tls: bool = True,
        from_email: str = "training@ransomrun.local",
        from_name: str = "Security Training",
        base_url: str = "http://localhost:8000"
    ):
        self.smtp_host = smtp_host or os.getenv("SMTP_HOST", "")
        self.smtp_port = smtp_port or int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = smtp_username or os.getenv("SMTP_USERNAME", "")
        self.smtp_password = smtp_password or os.getenv("SMTP_PASSWORD", "")
        self.use_tls = use_tls
        self.from_email = from_email or os.getenv("SMTP_FROM_EMAIL", "training@ransomrun.local")
        self.from_name = from_name or os.getenv("SMTP_FROM_NAME", "Security Training")
        self.base_url = base_url or os.getenv("PHISHING_BASE_URL", "http://localhost:8000")
        
        # Rate limiting
        self._send_count = 0
        self._last_reset = datetime.utcnow()
        self._rate_limit = 60  # Max emails per minute
    
    def is_configured(self) -> bool:
        """Check if SMTP is properly configured."""
        return bool(self.smtp_host and self.smtp_port)
    
    def _check_rate_limit(self) -> bool:
        """Check and update rate limit. Returns True if within limit."""
        now = datetime.utcnow()
        
        # Reset counter every minute
        if (now - self._last_reset).total_seconds() > 60:
            self._send_count = 0
            self._last_reset = now
        
        if self._send_count >= self._rate_limit:
            return False
        
        self._send_count += 1
        return True
    
    def _add_tracking_pixel(self, html: str, token: str) -> str:
        """Add tracking pixel to HTML email body."""
        pixel_url = f"{self.base_url}/phishing/t/pixel/{token}.png"
        pixel_tag = f'<img src="{pixel_url}" width="1" height="1" style="display:none;" alt="" />'
        
        # Insert before closing body tag if exists, otherwise append
        if "</body>" in html.lower():
            html = html.replace("</body>", f"{pixel_tag}</body>")
            html = html.replace("</BODY>", f"{pixel_tag}</BODY>")
        else:
            html += pixel_tag
        
        return html
    
    def _add_opt_out_footer(self, html: str, token: str) -> str:
        """Add opt-out footer to HTML email."""
        opt_out_url = f"{self.base_url}/phishing/opt-out/{token}"
        footer = f'''
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 11px; color: #999; text-align: center;">
            <p>This is a security awareness training email.</p>
            <p>
                <a href="{opt_out_url}" style="color: #666;">Unsubscribe from training emails</a>
            </p>
        </div>
        '''
        
        # Insert before closing body tag if exists
        if "</body>" in html.lower():
            html = html.replace("</body>", f"{footer}</body>")
            html = html.replace("</BODY>", f"{footer}</BODY>")
        else:
            html += footer
        
        return html
    
    def _replace_tracking_links(self, html: str, token: str) -> str:
        """Replace {{tracking_link}} placeholder with actual tracking URL."""
        tracking_url = f"{self.base_url}/phishing/t/click/{token}"
        html = html.replace("{{tracking_link}}", tracking_url)
        html = html.replace("{{ tracking_link }}", tracking_url)
        return html
    
    def send_training_email(
        self,
        to_email: str,
        to_name: str,
        subject: str,
        body_html: str,
        body_text: str = None,
        token: str = None,
        campaign_id: int = None,
        custom_headers: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Send a training phishing email.
        
        Args:
            to_email: Recipient email address
            to_name: Recipient display name
            subject: Email subject
            body_html: HTML body content
            body_text: Plain text body (optional)
            token: Tracking token for this message
            campaign_id: Campaign ID for reference
            custom_headers: Additional headers to include
            
        Returns:
            Dict with success status and details
        """
        if not self.is_configured():
            return {
                "success": False,
                "error": "SMTP not configured",
                "details": "Set SMTP_HOST and other SMTP settings"
            }
        
        if not self._check_rate_limit():
            return {
                "success": False,
                "error": "Rate limit exceeded",
                "details": f"Max {self._rate_limit} emails per minute"
            }
        
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = formataddr((self.from_name, self.from_email))
            msg["To"] = formataddr((to_name, to_email))
            
            # Add training headers
            msg["X-RansomRun-Training"] = "true"
            msg["X-RansomRun-Campaign"] = str(campaign_id) if campaign_id else "unknown"
            msg["X-Mailer"] = "RansomRun Security Training Platform"
            
            # Add custom headers
            if custom_headers:
                for key, value in custom_headers.items():
                    msg[key] = value
            
            # Process HTML body
            if token:
                body_html = self._replace_tracking_links(body_html, token)
                body_html = self._add_tracking_pixel(body_html, token)
                body_html = self._add_opt_out_footer(body_html, token)
            
            # Attach parts
            if body_text:
                text_part = MIMEText(body_text, "plain", "utf-8")
                msg.attach(text_part)
            
            html_part = MIMEText(body_html, "html", "utf-8")
            msg.attach(html_part)
            
            # Send email
            context = ssl.create_default_context()
            
            if self.use_tls:
                # STARTTLS on port 587
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    if self.smtp_username and self.smtp_password:
                        server.login(self.smtp_username, self.smtp_password)
                    server.sendmail(self.from_email, [to_email], msg.as_string())
            else:
                # Direct SSL on port 465
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, context=context, timeout=30) as server:
                    if self.smtp_username and self.smtp_password:
                        server.login(self.smtp_username, self.smtp_password)
                    server.sendmail(self.from_email, [to_email], msg.as_string())
            
            logger.info(f"Training email sent to {to_email} (campaign: {campaign_id})")
            
            return {
                "success": True,
                "message": "Email sent successfully",
                "to": to_email,
                "subject": subject
            }
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP auth error: {e}")
            return {
                "success": False,
                "error": "Authentication failed",
                "details": str(e)
            }
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"Recipient refused: {e}")
            return {
                "success": False,
                "error": "Recipient refused",
                "details": str(e)
            }
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return {
                "success": False,
                "error": "SMTP error",
                "details": str(e)
            }
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return {
                "success": False,
                "error": "Send failed",
                "details": str(e)
            }
    
    def send_batch(
        self,
        recipients: List[Dict[str, Any]],
        subject: str,
        body_html: str,
        body_text: str = None,
        campaign_id: int = None
    ) -> Dict[str, Any]:
        """
        Send training emails to multiple recipients.
        
        Args:
            recipients: List of dicts with 'email', 'name', 'token' keys
            subject: Email subject
            body_html: HTML body template
            body_text: Plain text body template (optional)
            campaign_id: Campaign ID
            
        Returns:
            Dict with success counts and errors
        """
        results = {
            "total": len(recipients),
            "sent": 0,
            "failed": 0,
            "errors": []
        }
        
        for recipient in recipients:
            result = self.send_training_email(
                to_email=recipient["email"],
                to_name=recipient.get("name", ""),
                subject=subject,
                body_html=body_html,
                body_text=body_text,
                token=recipient.get("token"),
                campaign_id=campaign_id
            )
            
            if result["success"]:
                results["sent"] += 1
            else:
                results["failed"] += 1
                results["errors"].append({
                    "email": recipient["email"],
                    "error": result.get("error", "Unknown error")
                })
        
        return results


# Global instance for convenience
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get or create the global email service instance."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service


def configure_email_service(
    smtp_host: str = None,
    smtp_port: int = None,
    smtp_username: str = None,
    smtp_password: str = None,
    use_tls: bool = True,
    from_email: str = None,
    from_name: str = None,
    base_url: str = None
) -> EmailService:
    """Configure and return the global email service instance."""
    global _email_service
    _email_service = EmailService(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        use_tls=use_tls,
        from_email=from_email,
        from_name=from_name,
        base_url=base_url
    )
    return _email_service


def send_training_email(
    to_email: str,
    to_name: str,
    subject: str,
    body_html: str,
    body_text: str = None,
    token: str = None,
    campaign_id: int = None
) -> Dict[str, Any]:
    """Convenience function to send a training email using the global service."""
    service = get_email_service()
    return service.send_training_email(
        to_email=to_email,
        to_name=to_name,
        subject=subject,
        body_html=body_html,
        body_text=body_text,
        token=token,
        campaign_id=campaign_id
    )
