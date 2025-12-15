import random
import string
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from app.core.config import settings
from prisma import Prisma
from prisma.enums import OtpStatusEnum, OtpTypeEnum # type: ignore
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig # type: ignore


class OTPService:

    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 10
    MAX_ATTEMPTS = 3
    RATE_LIMIT_SECONDS = 60

    def __init__(self, prisma: Prisma):
        self.prisma = prisma
        self.sms_provider = settings.sms_provider
        
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

    def generate_otp(self) -> str:
        return ''.join(random.choices(string.digits, k=self.OTP_LENGTH))

    def _calculate_expires_at(self) -> datetime:
        """Calculate OTP expiration time"""
        return datetime.now(timezone.utc) + timedelta(minutes=self.OTP_EXPIRY_MINUTES)

    def _check_and_handle_rate_limit(
        self, 
        recent_otp: Optional[any]
    ) -> Optional[Tuple[bool, str, Optional[dict]]]:
        """Check rate limit and return error if rate limited"""
        if recent_otp:
            seconds_remaining = (
                recent_otp.created_at + timedelta(seconds=self.RATE_LIMIT_SECONDS) - datetime.now(timezone.utc)
            ).total_seconds()
            if seconds_remaining > 0:
                return False, f"Please wait {int(seconds_remaining)} seconds before requesting a new OTP", None
        return None

    def _create_otp_data(
        self,
        otp_code: str,
        expires_at: datetime,
        otp_type: OtpTypeEnum,
        email: Optional[str] = None,
        phone_number: Optional[str] = None,
        country_code: Optional[str] = None
    ) -> dict:
        """Create OTP record data dictionary"""
        data = {
            "otp_code": otp_code,
            "otp_type": otp_type,
            "status": OtpStatusEnum.PENDING,
            "expires_at": expires_at,
            "attempts": 0,
            "max_attempts": self.MAX_ATTEMPTS,
        }
        if email:
            data["email"] = email
        if phone_number:
            data["phone_number"] = phone_number
        if country_code:
            data["country_code"] = country_code
        return data

    async def _handle_expired_otp(
        self, 
        otp_record: any, 
        tx: any,
        error_message: str = "OTP has expired. Please request a new one."
    ) -> Tuple[bool, str, Optional[dict]]:
        """Handle expired OTP by updating status"""
        await tx.otp_verifications.update(
            where={"id": otp_record.id},
            data={"status": OtpStatusEnum.EXPIRED}
        )
        return False, error_message, None

    async def _handle_max_attempts_exceeded(
        self, 
        otp_record: any, 
        tx: any,
        error_message: str = "Maximum verification attempts exceeded. Please request a new OTP."
    ) -> Tuple[bool, str, Optional[dict]]:
        """Handle max attempts exceeded by updating status"""
        await tx.otp_verifications.update(
            where={"id": otp_record.id},
            data={"status": OtpStatusEnum.FAILED}
        )
        return False, error_message, None

    async def _handle_invalid_otp(
        self,
        otp_record: any,
        updated_attempts: int,
        tx: any,
        error_message_prefix: str = "Invalid OTP"
    ) -> Tuple[bool, str, Optional[dict]]:
        """Handle invalid OTP by updating attempts"""
        attempts_remaining = otp_record.max_attempts - updated_attempts
        
        if attempts_remaining <= 0:
            await tx.otp_verifications.update(
                where={"id": otp_record.id},
                data={
                    "attempts": updated_attempts,
                    "status": OtpStatusEnum.FAILED
                }
            )
            return False, f"{error_message_prefix}. Maximum attempts exceeded. Please request a new OTP.", None
        
        await tx.otp_verifications.update(
            where={"id": otp_record.id},
            data={"attempts": updated_attempts}
        )
        return False, f"{error_message_prefix}. {attempts_remaining} attempts remaining.", None

    async def _handle_valid_otp(
        self,
        otp_record: any,
        updated_attempts: int,
        now: datetime,
        tx: any
    ) -> None:
        """Handle valid OTP by marking as verified"""
        await tx.otp_verifications.update(
            where={"id": otp_record.id},
            data={
                "attempts": updated_attempts,
                "status": OtpStatusEnum.VERIFIED,
                "verified_at": now
            }
        )

    async def _send_otp_common(
        self,
        recent_otp: Optional[any],
        invalidate_callback: callable,
        otp_type: OtpTypeEnum,
        send_callback: callable,
        otp_data: dict,
        success_data: dict,
        success_message: str = "OTP sent successfully",
        failure_message: str = "Failed to send OTP. Please try again.",
        error_message: str = "An error occurred while sending OTP"
    ) -> Tuple[bool, str, Optional[dict]]:
        """Common OTP sending logic"""
        try:
            rate_limit_error = self._check_and_handle_rate_limit(recent_otp)
            if rate_limit_error:
                return rate_limit_error

            await invalidate_callback()

            otp_code = self.generate_otp()
            expires_at = self._calculate_expires_at()

            otp_record = await self.prisma.otp_verifications.create(
                data=self._create_otp_data(
                    otp_code=otp_code,
                    expires_at=expires_at,
                    otp_type=otp_type,
                    **otp_data
                )
            )

            sent = await send_callback(otp_code)
            
            if not sent:
                return False, failure_message, None

            return True, success_message, {
                "id": otp_record.id,
                "expires_at": expires_at.isoformat(),
                "attempts_remaining": self.MAX_ATTEMPTS,
                "can_resend": False,
                **success_data
            }

        except Exception:
            return False, error_message, None

    async def send_otp(
        self, 
        phone_number: str, 
        country_code: str
    ) -> Tuple[bool, str, Optional[dict]]:
        recent_otp = await self._check_rate_limit(phone_number, country_code)
        return await self._send_otp_common(
            recent_otp=recent_otp,
            invalidate_callback=lambda: self._invalidate_existing_otps(phone_number, country_code),
            otp_type=OtpTypeEnum.PHONE_VERIFICATION,
            send_callback=lambda code: self._send_sms(),
            otp_data={
                "phone_number": phone_number,
                "country_code": country_code
            },
            success_data={
                "phone_number": phone_number,
                "country_code": country_code,
            }
        )

    async def _find_pending_otp(self, where_clause: dict) -> Optional[any]:
        """Find pending OTP record with given where clause"""
        return await self.prisma.otp_verifications.find_first(
            where={**where_clause, "status": OtpStatusEnum.PENDING},
            order={"created_at": "desc"}
        )

    async def _verify_otp_common(
        self,
        otp_record: any,
        otp_code: str,
        success_message: str,
        success_data: dict,
        not_found_message: str = "No pending OTP found. Please request a new one.",
        expired_message: str = "OTP has expired. Please request a new one.",
        max_attempts_message: str = "Maximum verification attempts exceeded. Please request a new OTP.",
        invalid_prefix: str = "Invalid OTP"
    ) -> Tuple[bool, str, Optional[dict]]:
        """Common OTP verification logic"""
        if not otp_record:
            return False, not_found_message, None

        now = datetime.now(timezone.utc)
        
        if now > otp_record.expires_at:
            async with self.prisma.tx() as tx:
                return await self._handle_expired_otp(otp_record, tx, expired_message)

        if otp_record.attempts >= otp_record.max_attempts:
            async with self.prisma.tx() as tx:
                return await self._handle_max_attempts_exceeded(otp_record, tx, max_attempts_message)

        updated_attempts = otp_record.attempts + 1
        
        async with self.prisma.tx() as tx:
            if otp_record.otp_code != otp_code:
                return await self._handle_invalid_otp(otp_record, updated_attempts, tx, invalid_prefix)
            else:
                await self._handle_valid_otp(otp_record, updated_attempts, now, tx)

        return True, success_message, success_data

    async def verify_otp(
        self,
        phone_number: str,
        country_code: str,
        otp_code: str
    ) -> Tuple[bool, str, Optional[dict]]:
        try:
            otp_record = await self._find_pending_otp({
                "phone_number": phone_number,
                "country_code": country_code,
            })
            
            return await self._verify_otp_common(
                otp_record=otp_record,
                otp_code=otp_code,
                success_message="Phone number verified successfully",
                success_data={
                    "verified": True,
                    "phone_number": phone_number,
                    "country_code": country_code,
                }
            )
        except Exception:
            return False, "An error occurred while verifying OTP", None

    async def send_email_otp(self, email: str) -> Tuple[bool, str, Optional[dict]]:
        recent_otp = await self._check_email_rate_limit(email)
        return await self._send_otp_common(
            recent_otp=recent_otp,
            invalidate_callback=lambda: self._invalidate_existing_email_otps(email, OtpTypeEnum.EMAIL_VERIFICATION),
            otp_type=OtpTypeEnum.EMAIL_VERIFICATION,
            send_callback=lambda code: self._send_email(email, code),
            otp_data={"email": email},
            success_data={"email": email}
        )

    async def verify_email_otp(self, email: str, otp_code: str) -> Tuple[bool, str, Optional[dict]]:
        try:
            otp_record = await self._find_pending_otp({
                "email": email,
                "otp_type": OtpTypeEnum.EMAIL_VERIFICATION,
            })
            
            return await self._verify_otp_common(
                otp_record=otp_record,
                otp_code=otp_code,
                success_message="Email verified successfully",
                success_data={
                    "verified": True,
                    "email": email,
                }
            )
        except Exception:
            return False, "An error occurred while verifying OTP", None

    async def _send_email(self, email: str, otp_code: str) -> bool:
        try:
            if not self.mail_config:
                return True

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
                subtype="html"
            )

            await self.fast_mail.send_message(message)
            return True

        except Exception:
            return False

    async def _check_email_rate_limit(self, email: str) -> Optional[any]:
        cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=self.RATE_LIMIT_SECONDS)
        
        recent_otp = await self.prisma.otp_verifications.find_first(
            where={
                "email": email,
                "created_at": {"gte": cutoff_time}
            },
            order={"created_at": "desc"}
        )
        
        return recent_otp

    async def send_password_reset_otp(self, email: str) -> Tuple[bool, str, Optional[dict]]:
        recent_otp = await self._check_email_rate_limit(email)
        rate_limit_error = self._check_and_handle_rate_limit(recent_otp)
        if rate_limit_error:
            if rate_limit_error[0] is False:
                return False, rate_limit_error[1].replace("requesting a new OTP", "requesting another code"), None
            return rate_limit_error
        
        return await self._send_otp_common(
            recent_otp=None,
            invalidate_callback=lambda: self._invalidate_existing_email_otps(email, OtpTypeEnum.PASSWORD_RESET),
            otp_type=OtpTypeEnum.PASSWORD_RESET,
            send_callback=lambda code: self._send_email(email, code),
            otp_data={"email": email},
            success_data={"email": email},
            success_message="Password reset code sent successfully",
            failure_message="Failed to send password reset code. Please try again.",
            error_message="An error occurred while sending reset code"
        )

    async def verify_password_reset_otp(self, email: str, otp_code: str) -> Tuple[bool, str, Optional[dict]]:
        try:
            otp_record = await self._find_pending_otp({
                "email": email,
                "otp_type": OtpTypeEnum.PASSWORD_RESET,
            })
            
            return await self._verify_otp_common(
                otp_record=otp_record,
                otp_code=otp_code,
                success_message="Password reset code verified",
                success_data={
                    "verified": True,
                    "email": email,
                },
                not_found_message="No pending password reset request found. Please request a new code.",
                expired_message="Password reset code has expired. Please request a new one.",
                max_attempts_message="Maximum attempts exceeded. Please request a new password reset code.",
                invalid_prefix="Invalid code"
            )
        except Exception:
            return False, "An error occurred while verifying reset code", None

    async def _invalidate_existing_email_otps(self, email: str, otp_type: OtpTypeEnum) -> None:
        await self.prisma.otp_verifications.update_many(
            where={
                "email": email,
                "status": OtpStatusEnum.PENDING,
                "otp_type": otp_type,
            },
            data={"status": OtpStatusEnum.EXPIRED}
        )

    async def _send_sms(self) -> bool:
        try:
            if self.sms_provider == "twilio":
                return await self._send_via_twilio()
            else:
                return True
        except Exception:
            return False

    def _send_via_twilio(self) -> bool:
        try:
            return True

        except Exception:
            return False

    async def _check_rate_limit(
        self, 
        phone_number: str, 
        country_code: str
    ) -> Optional[any]:
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
        await self.prisma.otp_verifications.update_many(
            where={
                "phone_number": phone_number,
                "country_code": country_code,
                "status": OtpStatusEnum.PENDING,
            },
            data={"status": OtpStatusEnum.EXPIRED}
        )

    async def cleanup_expired_otps(self) -> int:
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
            
            result = await self.prisma.otp_verifications.delete_many(
                where={
                    "created_at": {"lt": cutoff_time}
                }
            )
            
            return result
        except Exception:
            return 0

