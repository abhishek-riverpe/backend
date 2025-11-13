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

            logger.info(f"[OTP] Created OTP record: {otp_record.otp_id}")

            # Send OTP via SMS
            sms_sent = await self._send_sms(full_phone, otp_code)
            
            if not sms_sent:
                logger.error(f"[OTP] Failed to send SMS to {full_phone}")
                return False, "Failed to send OTP. Please try again.", None

            logger.info(f"[OTP] OTP sent successfully to {full_phone}")
            
            return True, "OTP sent successfully", {
                "otp_id": otp_record.otp_id,
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
                    where={"otp_id": otp_record.otp_id},
                    data={"status": OtpStatusEnum.EXPIRED}
                )
                return False, "OTP has expired. Please request a new one.", None

            # Check max attempts
            if otp_record.attempts >= otp_record.max_attempts:
                logger.warning(f"[OTP] Max attempts exceeded for {full_phone}")
                await self.prisma.otp_verifications.update(
                    where={"otp_id": otp_record.otp_id},
                    data={"status": OtpStatusEnum.FAILED}
                )
                return False, "Maximum verification attempts exceeded. Please request a new OTP.", None

            # Increment attempts
            updated_attempts = otp_record.attempts + 1
            await self.prisma.otp_verifications.update(
                where={"otp_id": otp_record.otp_id},
                data={"attempts": updated_attempts}
            )

            # Verify OTP code
            if otp_record.otp_code != otp_code:
                attempts_remaining = otp_record.max_attempts - updated_attempts
                logger.warning(f"[OTP] Invalid OTP for {full_phone}, {attempts_remaining} attempts remaining")
                
                if attempts_remaining <= 0:
                    await self.prisma.otp_verifications.update(
                        where={"otp_id": otp_record.otp_id},
                        data={"status": OtpStatusEnum.FAILED}
                    )
                    return False, "Maximum verification attempts exceeded. Please request a new OTP.", None
                
                return False, f"Invalid OTP. {attempts_remaining} attempts remaining.", None

            # OTP is valid - mark as verified
            await self.prisma.otp_verifications.update(
                where={"otp_id": otp_record.otp_id},
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

