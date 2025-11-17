"""
Email Service

Handles sending transactional emails including password change notifications.
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Service for sending transactional emails"""
    
    def __init__(self):
        # Initialize FastMail configuration
        self.mail_config = None
        if settings.mail_username and settings.mail_password:
            self.mail_config = ConnectionConfig(
                MAIL_USERNAME=settings.mail_username,
                MAIL_PASSWORD=settings.mail_password,
                MAIL_FROM=settings.mail_from or settings.mail_username,
                MAIL_PORT=settings.mail_port,
                MAIL_SERVER=settings.mail_server,
                MAIL_FROM_NAME=settings.mail_from_name or "RiverPe",
                MAIL_STARTTLS=settings.mail_starttls,
                MAIL_SSL_TLS=settings.mail_ssl_tls,
                USE_CREDENTIALS=settings.use_credentials,
                VALIDATE_CERTS=settings.validate_certs
            )
            self.fast_mail = FastMail(self.mail_config)
        else:
            logger.warning("[EMAIL] Email configuration not found. Email service will run in mock mode.")
    
    async def send_password_change_notification(
        self,
        email: str,
        user_name: str,
        device_info: Dict[str, Any],
        location_info: Dict[str, Any],
        ip_address: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> bool:
        """
        Send password change notification email with security details.
        
        Args:
            email: Recipient email address
            user_name: User's full name
            device_info: Device information dict (device_type, os_name, browser_name, etc.)
            location_info: Location information dict (city, country, etc.)
            ip_address: IP address from which password was changed
            timestamp: When password was changed
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        if not timestamp:
            timestamp = datetime.now()
        
        # Format device information
        device_type = device_info.get("device_type") or "Unknown Device"
        os_name = device_info.get("os_name") or "Unknown OS"
        os_version = device_info.get("os_version") or ""
        browser_name = device_info.get("browser_name") or "Unknown Browser"
        browser_version = device_info.get("browser_version") or ""
        
        device_description = f"{device_type}"
        if os_name != "Unknown OS":
            device_description += f" ({os_name}"
            if os_version:
                device_description += f" {os_version}"
            device_description += ")"
        if browser_name != "Unknown Browser":
            device_description += f" - {browser_name}"
            if browser_version:
                device_description += f" {browser_version}"
        
        # Format location information
        city = location_info.get("city") or "Unknown City"
        country = location_info.get("country") or "Unknown Country"
        location_description = f"{city}, {country}"
        
        # Format timestamp
        formatted_time = timestamp.strftime("%B %d, %Y at %I:%M %p UTC")
        
        # Create email HTML body
        email_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #1F73FF; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ background-color: #f9f9f9; padding: 30px; border: 1px solid #ddd; border-top: none; }}
        .alert-box {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
        .info-box {{ background-color: #e7f3ff; border-left: 4px solid #1F73FF; padding: 15px; margin: 15px 0; }}
        .detail-row {{ margin: 10px 0; padding: 10px; background-color: white; border-radius: 4px; }}
        .detail-label {{ font-weight: bold; color: #555; }}
        .detail-value {{ color: #333; margin-top: 5px; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
        .button {{ display: inline-block; padding: 12px 24px; background-color: #1F73FF; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Password Changed</h1>
        </div>
        <div class="content">
            <p>Hello {user_name},</p>
            
            <p>This is a security notification to confirm that your password has been successfully changed.</p>
            
            <div class="alert-box">
                <strong>⚠️ Important Security Notice:</strong><br>
                If you did not make this change, please contact our support team immediately and secure your account.
            </div>
            
            <h3>Change Details:</h3>
            <div class="info-box">
                <div class="detail-row">
                    <div class="detail-label">Date & Time:</div>
                    <div class="detail-value">{formatted_time}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Device:</div>
                    <div class="detail-value">{device_description}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Location:</div>
                    <div class="detail-value">{location_description}</div>
                </div>
                {f'<div class="detail-row"><div class="detail-label">IP Address:</div><div class="detail-value">{ip_address}</div></div>' if ip_address else ''}
            </div>
            
            <h3>Security Tips:</h3>
            <ul>
                <li>Always use a strong, unique password</li>
                <li>Never share your password with anyone</li>
                <li>Enable two-factor authentication if available</li>
                <li>Log out from shared or public devices</li>
                <li>Review your account activity regularly</li>
            </ul>
            
            <p>If you have any concerns about your account security, please contact our support team immediately.</p>
            
            <p>Best regards,<br>
            <strong>RiverPe Security Team</strong></p>
        </div>
        <div class="footer">
            <p>This is an automated security notification. Please do not reply to this email.</p>
            <p>&copy; 2024 RiverPe. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
        
        try:
            if not self.mail_config:
                logger.info(f"[EMAIL] MOCK - Password change notification to {email}")
                logger.info(f"[EMAIL] Device: {device_description}, Location: {location_description}")
                return True
            
            # Create email message
            message = MessageSchema(
                subject="🔒 Password Changed - Security Notification",
                recipients=[email],
                body=email_html,
                subtype="html"
            )
            
            # Send email
            await self.fast_mail.send_message(message)
            logger.info(f"[EMAIL] Password change notification sent successfully to {email}")
            return True
            
        except Exception as e:
            logger.error(f"[EMAIL] Error sending password change notification: {str(e)}", exc_info=True)
            return False


# Global instance
email_service = EmailService()

