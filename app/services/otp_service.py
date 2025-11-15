"""
OTP Service

Handles OTP generation, sending, verification, and cleanup.
Includes rate limiting and security features.
"""

import random
import string
import httpx
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from app.core.config import settings
from prisma import Prisma
from prisma.enums import OtpStatusEnum, OtpTypeEnum
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

logger = logging.getLogger(__name__)


class OTPService:
    """Service for managing OTP operations"""

    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 10
    MAX_ATTEMPTS = 3
    RATE_LIMIT_SECONDS = 60  # Can't request new OTP within 60 seconds

    def __init__(self, prisma: Prisma):
        self.prisma = prisma
        self.sms_provider = settings.sms_provider  # 'twilio' or 'mock'
        
        # Initialize FastMail configuration
        self.mail_config = None
        if settings.mail_username and settings.mail_password:
            self.mail_config = ConnectionConfig(
                MAIL_USERNAME=settings.mail_username,
                MAIL_PASSWORD=settings.mail_password,
                MAIL_FROM=settings.mail_from or settings.mail_username,
                MAIL_PORT=settings.mail_port,
                MAIL_SERVER=settings.mail_server,
                MAIL_FROM_NAME=settings.mail_from_name,
                MAIL_STARTTLS=settings.mail_starttls,
                MAIL_SSL_TLS=settings.mail_ssl_tls,
                USE_CREDENTIALS=settings.use_credentials,
                VALIDATE_CERTS=settings.validate_certs
            )
            self.fast_mail = FastMail(self.mail_config)
        else:
            logger.warning("[OTP] Email configuration not found. Email OTP will run in mock mode.")

    async def generate_otp(self) -> str:
        """
        Generate a random 6-digit OTP code
        
        Returns:
            str: 6-digit numeric OTP
        """
        return ''.join(random.choices(string.digits, k=self.OTP_LENGTH))

    async def send_otp(
        self, 
        phone_number: str, 
        country_code: str
    ) -> Tuple[bool, str, Optional[dict]]:
        """
        Send OTP to phone number
        
        Args:
            phone_number: Phone number without country code
            country_code: Country code (e.g., +1, +91)
            
        Returns:
            Tuple of (success, message, data)
        """
        try:
            full_phone = f"{country_code}{phone_number}"
            logger.info(f"[OTP] Sending OTP to {full_phone}")

            # Check rate limiting - prevent spam
            recent_otp = await self._check_rate_limit(phone_number, country_code)
            if recent_otp:
                seconds_remaining = (
                    recent_otp.created_at + timedelta(seconds=self.RATE_LIMIT_SECONDS) - datetime.now(timezone.utc)
                ).total_seconds()
                if seconds_remaining > 0:
                    logger.warning(f"[OTP] Rate limit hit for {full_phone}")
                    return False, f"Please wait {int(seconds_remaining)} seconds before requesting a new OTP", None

            # Invalidate any existing pending OTPs for this number
            await self._invalidate_existing_otps(phone_number, country_code)

            # Generate new OTP
            otp_code = await self.generate_otp()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.OTP_EXPIRY_MINUTES)

            # Save OTP to database
            otp_record = await self.prisma.otp_verifications.create(
                data={
                    "phone_number": phone_number,
                    "country_code": country_code,
                    "otp_code": otp_code,
                    "otp_type": OtpTypeEnum.PHONE_VERIFICATION,
                    "status": OtpStatusEnum.PENDING,
                    "expires_at": expires_at,
                    "attempts": 0,
                    "max_attempts": self.MAX_ATTEMPTS,
                }
            )

            logger.info(f"[OTP] Created OTP record: {otp_record.id}")

            # Send OTP via SMS
            sms_sent = await self._send_sms(full_phone, otp_code)
            
            if not sms_sent:
                logger.error(f"[OTP] Failed to send SMS to {full_phone}")
                return False, "Failed to send OTP. Please try again.", None

            logger.info(f"[OTP] OTP sent successfully to {full_phone}")
            
            return True, "OTP sent successfully", {
                "otp_id": otp_record.id,
                "phone_number": phone_number,
                "country_code": country_code,
                "expires_at": expires_at.isoformat(),
                "attempts_remaining": self.MAX_ATTEMPTS,
                "can_resend": False,
            }

        except Exception as e:
            logger.error(f"[OTP] Error sending OTP: {str(e)}", exc_info=True)
            return False, "An error occurred while sending OTP", None

    async def verify_otp(
        self,
        phone_number: str,
        country_code: str,
        otp_code: str
    ) -> Tuple[bool, str, Optional[dict]]:
        """
        Verify OTP code
        
        Args:
            phone_number: Phone number without country code
            country_code: Country code
            otp_code: 6-digit OTP to verify
            
        Returns:
            Tuple of (success, message, data)
        """
        try:
            full_phone = f"{country_code}{phone_number}"
            logger.info(f"[OTP] Verifying OTP for {full_phone}")

            # Find the most recent pending OTP
            otp_record = await self.prisma.otp_verifications.find_first(
                where={
                    "phone_number": phone_number,
                    "country_code": country_code,
                    "status": OtpStatusEnum.PENDING,
                },
                order={"created_at": "desc"}
            )

            if not otp_record:
                logger.warning(f"[OTP] No pending OTP found for {full_phone}")
                return False, "No pending OTP found. Please request a new one.", None

            # Check if OTP has expired
            if datetime.now(timezone.utc) > otp_record.expires_at:
                logger.warning(f"[OTP] Expired OTP for {full_phone}")
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.EXPIRED}
                )
                return False, "OTP has expired. Please request a new one.", None

            # Check max attempts
            if otp_record.attempts >= otp_record.max_attempts:
                logger.warning(f"[OTP] Max attempts exceeded for {full_phone}")
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.FAILED}
                )
                return False, "Maximum verification attempts exceeded. Please request a new OTP.", None

            # Increment attempts
            updated_attempts = otp_record.attempts + 1
            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={"attempts": updated_attempts}
            )

            # Verify OTP code
            if otp_record.otp_code != otp_code:
                attempts_remaining = otp_record.max_attempts - updated_attempts
                logger.warning(f"[OTP] Invalid OTP for {full_phone}, {attempts_remaining} attempts remaining")
                
                if attempts_remaining <= 0:
                    await self.prisma.otp_verifications.update(
                        where={"id": otp_record.id},
                        data={"status": OtpStatusEnum.FAILED}
                    )
                    return False, "Maximum verification attempts exceeded. Please request a new OTP.", None
                
                return False, f"Invalid OTP. {attempts_remaining} attempts remaining.", None

            # OTP is valid - mark as verified
            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={
                    "status": OtpStatusEnum.VERIFIED,
                    "verified_at": datetime.now(timezone.utc)
                }
            )

            logger.info(f"[OTP] Successfully verified OTP for {full_phone}")
            return True, "Phone number verified successfully", {
                "verified": True,
                "phone_number": phone_number,
                "country_code": country_code,
            }

        except Exception as e:
            logger.error(f"[OTP] Error verifying OTP: {str(e)}", exc_info=True)
            return False, "An error occurred while verifying OTP", None

    async def send_email_otp(self, email: str) -> Tuple[bool, str, Optional[dict]]:
        """
        Send OTP to email address
        
        Args:
            email: Email address to send OTP to
            
        Returns:
            Tuple of (success, message, data)
        """
        try:
            logger.info(f"[OTP] Sending email OTP to {email}")

            # Check rate limiting - prevent spam
            recent_otp = await self._check_email_rate_limit(email)
            if recent_otp:
                seconds_remaining = (
                    recent_otp.created_at + timedelta(seconds=self.RATE_LIMIT_SECONDS) - datetime.now(timezone.utc)
                ).total_seconds()
                if seconds_remaining > 0:
                    logger.warning(f"[OTP] Rate limit hit for {email}")
                    return False, f"Please wait {int(seconds_remaining)} seconds before requesting a new OTP", None

            # Invalidate any existing pending OTPs for this email
            await self._invalidate_existing_email_otps(email)

            # Generate new OTP
            otp_code = await self.generate_otp()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.OTP_EXPIRY_MINUTES)

            # Save OTP to database
            otp_record = await self.prisma.otp_verifications.create(
                data={
                    "email": email,
                    "otp_code": otp_code,
                    "otp_type": OtpTypeEnum.EMAIL_VERIFICATION,
                    "status": OtpStatusEnum.PENDING,
                    "expires_at": expires_at,
                    "attempts": 0,
                    "max_attempts": self.MAX_ATTEMPTS,
                }
            )

            logger.info(f"[OTP] Created email OTP record: {otp_record.id}")

            # Send OTP via email
            email_sent = await self._send_email(email, otp_code)
            
            if not email_sent:
                logger.error(f"[OTP] Failed to send email to {email}")
                return False, "Failed to send OTP. Please try again.", None

            logger.info(f"[OTP] OTP sent successfully to {email}")
            
            return True, "OTP sent successfully", {
                "otp_id": otp_record.id,
                "email": email,
                "expires_at": expires_at.isoformat(),
                "attempts_remaining": self.MAX_ATTEMPTS,
                "can_resend": False,
            }

        except Exception as e:
            logger.error(f"[OTP] Error sending email OTP: {str(e)}", exc_info=True)
            return False, "An error occurred while sending OTP", None

    async def verify_email_otp(self, email: str, otp_code: str) -> Tuple[bool, str, Optional[dict]]:
        """
        Verify email OTP code
        
        Args:
            email: Email address
            otp_code: 6-digit OTP to verify
            
        Returns:
            Tuple of (success, message, data)
        """
        try:
            logger.info(f"[OTP] Verifying email OTP for {email}")

            # Find the most recent pending OTP
            otp_record = await self.prisma.otp_verifications.find_first(
                where={
                    "email": email,
                    "status": OtpStatusEnum.PENDING,
                    "otp_type": OtpTypeEnum.EMAIL_VERIFICATION,
                },
                order={"created_at": "desc"}
            )

            if not otp_record:
                logger.warning(f"[OTP] No pending email OTP found for {email}")
                return False, "No pending OTP found. Please request a new one.", None

            # Check if OTP has expired
            if datetime.now(timezone.utc) > otp_record.expires_at:
                logger.warning(f"[OTP] Expired email OTP for {email}")
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.EXPIRED}
                )
                return False, "OTP has expired. Please request a new one.", None

            # Check max attempts
            if otp_record.attempts >= otp_record.max_attempts:
                logger.warning(f"[OTP] Max attempts exceeded for {email}")
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.FAILED}
                )
                return False, "Maximum verification attempts exceeded. Please request a new OTP.", None

            # Increment attempts
            updated_attempts = otp_record.attempts + 1
            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={"attempts": updated_attempts}
            )

            # Verify OTP code
            if otp_record.otp_code != otp_code:
                attempts_remaining = otp_record.max_attempts - updated_attempts
                logger.warning(f"[OTP] Invalid email OTP for {email}, {attempts_remaining} attempts remaining")
                
                if attempts_remaining <= 0:
                    await self.prisma.otp_verifications.update(
                        where={"id": otp_record.id},
                        data={"status": OtpStatusEnum.FAILED}
                    )
                    return False, "Maximum verification attempts exceeded. Please request a new OTP.", None
                
                return False, f"Invalid OTP. {attempts_remaining} attempts remaining.", None

            # OTP is valid - mark as verified
            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={
                    "status": OtpStatusEnum.VERIFIED,
                    "verified_at": datetime.now(timezone.utc)
                }
            )

            logger.info(f"[OTP] Successfully verified email OTP for {email}")
            return True, "Email verified successfully", {
                "verified": True,
                "email": email,
            }

        except Exception as e:
            logger.error(f"[OTP] Error verifying email OTP: {str(e)}", exc_info=True)
            return False, "An error occurred while verifying OTP", None

    async def _send_email(self, email: str, otp_code: str) -> bool:
        """
        Send email via FastMail
        
        Args:
            email: Email address
            otp_code: OTP code to send
            
        Returns:
            bool: True if sent successfully
        """
        try:
            if not self.mail_config:
                # Mock mode - just log the OTP
                logger.info(f"[OTP] MOCK EMAIL - To: {email}, Code: {otp_code}")
                return True

            # Create email message
            message = MessageSchema(
                subject="Your RiverPe Verification Code",
                recipients=[email],
                body=f"""
                <html>
                    <body style="font-family: Arial, sans-serif; padding: 20px;">
                        <h2 style="color: #333;">Email Verification</h2>
                        <p>Your RiverPe verification code is:</p>
                        <h1 style="color: #4F46E5; font-size: 32px; letter-spacing: 5px;">{otp_code}</h1>
                        <p>This code will expire in 10 minutes.</p>
                        <p style="color: #666; font-size: 12px; margin-top: 30px;">
                            If you didn't request this code, please ignore this email.
                        </p>
                    </body>
                </html>
                """,
                subtype=MessageType.html
            )

            # Send email
            await self.fast_mail.send_message(message)
            logger.info(f"[OTP] Email sent successfully to {email}")
            return True

        except Exception as e:
            logger.error(f"[OTP] Email sending error: {str(e)}", exc_info=True)
            return False

    async def _check_email_rate_limit(self, email: str) -> Optional[any]:
        """
        Check if rate limit has been hit for email
        
        Returns:
            OTP record if within rate limit window, None otherwise
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=self.RATE_LIMIT_SECONDS)
        
        recent_otp = await self.prisma.otp_verifications.find_first(
            where={
                "email": email,
                "created_at": {"gte": cutoff_time}
            },
            order={"created_at": "desc"}
        )
        
        return recent_otp

    async def _invalidate_existing_email_otps(self, email: str) -> None:
        """
        Mark all existing pending email OTPs as expired
        """
        await self.prisma.otp_verifications.update_many(
            where={
                "email": email,
                "status": OtpStatusEnum.PENDING,
                "otp_type": OtpTypeEnum.EMAIL_VERIFICATION,
            },
            data={"status": OtpStatusEnum.EXPIRED}
        )

    async def _send_sms(self, phone_number: str, otp_code: str) -> bool:
        """
        Send SMS via provider (Twilio or mock)
        
        Args:
            phone_number: Full phone number with country code
            otp_code: OTP code to send
            
        Returns:
            bool: True if sent successfully
        """
        try:
            if self.sms_provider == "twilio":
                return await self._send_via_twilio(phone_number, otp_code)
            else:
                # Mock mode - just log the OTP
                logger.info(f"[OTP] MOCK SMS - Phone: {phone_number}, Code: {otp_code}")
                return True
        except Exception as e:
            logger.error(f"[OTP] SMS sending error: {str(e)}", exc_info=True)
            return False

    async def _send_via_twilio(self, phone_number: str, otp_code: str) -> bool:
        """
        Send SMS via Twilio
        
        Args:
            phone_number: Full phone number with country code
            otp_code: OTP code to send
            
        Returns:
            bool: True if sent successfully
        """
        try:
            # Twilio API integration
            account_sid = settings.twilio_account_sid
            auth_token = settings.twilio_auth_token
            from_number = settings.twilio_phone_number

            if not all([account_sid, auth_token, from_number]):
                logger.error("[OTP] Twilio credentials not configured")
                return False

            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    auth=(account_sid, auth_token),
                    data={
                        "To": phone_number,
                        "From": from_number,
                        "Body": f"Your RiverPe verification code is: {otp_code}. Valid for 10 minutes."
                    },
                    timeout=10.0
                )
                
                if response.status_code == 201:
                    logger.info(f"[OTP] Twilio SMS sent successfully to {phone_number}")
                    return True
                else:
                    logger.error(f"[OTP] Twilio error: {response.status_code} - {response.text}")
                    return False

        except Exception as e:
            logger.error(f"[OTP] Twilio sending error: {str(e)}", exc_info=True)
            return False

    async def _check_rate_limit(
        self, 
        phone_number: str, 
        country_code: str
    ) -> Optional[any]:
        """
        Check if rate limit has been hit
        
        Returns:
            OTP record if within rate limit window, None otherwise
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=self.RATE_LIMIT_SECONDS)
        
        recent_otp = await self.prisma.otp_verifications.find_first(
            where={
                "phone_number": phone_number,
                "country_code": country_code,
                "created_at": {"gte": cutoff_time}
            },
            order={"created_at": "desc"}
        )
        
        return recent_otp

    async def _invalidate_existing_otps(
        self, 
        phone_number: str, 
        country_code: str
    ) -> None:
        """
        Mark all existing pending OTPs as expired
        """
        await self.prisma.otp_verifications.update_many(
            where={
                "phone_number": phone_number,
                "country_code": country_code,
                "status": OtpStatusEnum.PENDING,
            },
            data={"status": OtpStatusEnum.EXPIRED}
        )

    async def cleanup_expired_otps(self) -> int:
        """
        Clean up expired OTPs (can be run as a background task)
        
        Returns:
            Number of records deleted
        """
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
            
            result = await self.prisma.otp_verifications.delete_many(
                where={
                    "created_at": {"lt": cutoff_time}
                }
            )
            
            logger.info(f"[OTP] Cleaned up {result} expired OTP records")
            return result
        except Exception as e:
            logger.error(f"[OTP] Cleanup error: {str(e)}", exc_info=True)
            return 0

