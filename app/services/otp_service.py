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

    async def generate_otp(self) -> str:
        return ''.join(random.choices(string.digits, k=self.OTP_LENGTH))

    async def send_otp(
        self, 
        phone_number: str, 
        country_code: str
    ) -> Tuple[bool, str, Optional[dict]]:
        try:
            recent_otp = await self._check_rate_limit(phone_number, country_code)
            if recent_otp:
                seconds_remaining = (
                    recent_otp.created_at + timedelta(seconds=self.RATE_LIMIT_SECONDS) - datetime.now(timezone.utc)
                ).total_seconds()
                if seconds_remaining > 0:
                    return False, f"Please wait {int(seconds_remaining)} seconds before requesting a new OTP", None

            await self._invalidate_existing_otps(phone_number, country_code)

            otp_code = await self.generate_otp()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.OTP_EXPIRY_MINUTES)

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

            sms_sent = await self._send_sms()
            
            if not sms_sent:
                return False, "Failed to send OTP. Please try again.", None

            return True, "OTP sent successfully", {
                "id": otp_record.id,
                "phone_number": phone_number,
                "country_code": country_code,
                "expires_at": expires_at.isoformat(),
                "attempts_remaining": self.MAX_ATTEMPTS,
                "can_resend": False,
            }

        except Exception:
            return False, "An error occurred while sending OTP", None

    async def verify_otp(
        self,
        phone_number: str,
        country_code: str,
        otp_code: str
    ) -> Tuple[bool, str, Optional[dict]]:
        try:
            otp_record = await self.prisma.otp_verifications.find_first(
                where={
                    "phone_number": phone_number,
                    "country_code": country_code,
                    "status": OtpStatusEnum.PENDING,
                },
                order={"created_at": "desc"}
            )

            if not otp_record:
                return False, "No pending OTP found. Please request a new one.", None

            if datetime.now(timezone.utc) > otp_record.expires_at:
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.EXPIRED}
                )
                return False, "OTP has expired. Please request a new one.", None

            if otp_record.attempts >= otp_record.max_attempts:
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.FAILED}
                )
                return False, "Maximum verification attempts exceeded. Please request a new OTP.", None

            updated_attempts = otp_record.attempts + 1
            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={"attempts": updated_attempts}
            )

            if otp_record.otp_code != otp_code:
                attempts_remaining = otp_record.max_attempts - updated_attempts
                
                if attempts_remaining <= 0:
                    await self.prisma.otp_verifications.update(
                        where={"id": otp_record.id},
                        data={"status": OtpStatusEnum.FAILED}
                    )
                    return False, "Maximum verification attempts exceeded. Please request a new OTP.", None
                
                return False, f"Invalid OTP. {attempts_remaining} attempts remaining.", None

            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={
                    "status": OtpStatusEnum.VERIFIED,
                    "verified_at": datetime.now(timezone.utc)
                }
            )

            return True, "Phone number verified successfully", {
                "verified": True,
                "phone_number": phone_number,
                "country_code": country_code,
            }

        except Exception:
            return False, "An error occurred while verifying OTP", None

    async def send_email_otp(self, email: str) -> Tuple[bool, str, Optional[dict]]:
        try:
            recent_otp = await self._check_email_rate_limit(email)
            if recent_otp:
                seconds_remaining = (
                    recent_otp.created_at + timedelta(seconds=self.RATE_LIMIT_SECONDS) - datetime.now(timezone.utc)
                ).total_seconds()
                if seconds_remaining > 0:
                    return False, f"Please wait {int(seconds_remaining)} seconds before requesting a new OTP", None

            await self._invalidate_existing_email_otps(email, OtpTypeEnum.EMAIL_VERIFICATION)

            otp_code = await self.generate_otp()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.OTP_EXPIRY_MINUTES)

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

            email_sent = await self._send_email(email, otp_code)
            
            if not email_sent:
                return False, "Failed to send OTP. Please try again.", None

            return True, "OTP sent successfully", {
                "id": otp_record.id,
                "email": email,
                "expires_at": expires_at.isoformat(),
                "attempts_remaining": self.MAX_ATTEMPTS,
                "can_resend": False,
            }

        except Exception:
            return False, "An error occurred while sending OTP", None

    async def verify_email_otp(self, email: str, otp_code: str) -> Tuple[bool, str, Optional[dict]]:
        try:
            otp_record = await self.prisma.otp_verifications.find_first(
                where={
                    "email": email,
                    "status": OtpStatusEnum.PENDING,
                    "otp_type": OtpTypeEnum.EMAIL_VERIFICATION,
                },
                order={"created_at": "desc"}
            )

            if not otp_record:
                return False, "No pending OTP found. Please request a new one.", None

            if datetime.now(timezone.utc) > otp_record.expires_at:
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.EXPIRED}
                )
                return False, "OTP has expired. Please request a new one.", None

            if otp_record.attempts >= otp_record.max_attempts:
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.FAILED}
                )
                return False, "Maximum verification attempts exceeded. Please request a new OTP.", None

            updated_attempts = otp_record.attempts + 1
            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={"attempts": updated_attempts}
            )

            if otp_record.otp_code != otp_code:
                attempts_remaining = otp_record.max_attempts - updated_attempts
                
                if attempts_remaining <= 0:
                    await self.prisma.otp_verifications.update(
                        where={"id": otp_record.id},
                        data={"status": OtpStatusEnum.FAILED}
                    )
                    return False, "Maximum verification attempts exceeded. Please request a new OTP.", None
                
                return False, f"Invalid OTP. {attempts_remaining} attempts remaining.", None

            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={
                    "status": OtpStatusEnum.VERIFIED,
                    "verified_at": datetime.now(timezone.utc)
                }
            )

            return True, "Email verified successfully", {
                "verified": True,
                "email": email,
            }

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
        try:
            recent_otp = await self._check_email_rate_limit(email)
            if recent_otp:
                seconds_remaining = (
                    recent_otp.created_at + timedelta(seconds=self.RATE_LIMIT_SECONDS) - datetime.now(timezone.utc)
                ).total_seconds()
                if seconds_remaining > 0:
                    return False, f"Please wait {int(seconds_remaining)} seconds before requesting another code", None

            await self._invalidate_existing_email_otps(email, OtpTypeEnum.PASSWORD_RESET)

            otp_code = await self.generate_otp()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.OTP_EXPIRY_MINUTES)

            otp_record = await self.prisma.otp_verifications.create(
                data={
                    "email": email,
                    "otp_code": otp_code,
                    "otp_type": OtpTypeEnum.PASSWORD_RESET,
                    "status": OtpStatusEnum.PENDING,
                    "expires_at": expires_at,
                    "attempts": 0,
                    "max_attempts": self.MAX_ATTEMPTS,
                }
            )

            email_sent = await self._send_email(email, otp_code)

            if not email_sent:
                return False, "Failed to send password reset code. Please try again.", None

            return True, "Password reset code sent successfully", {
                "id": otp_record.id,
                "email": email,
                "expires_at": expires_at.isoformat(),
                "attempts_remaining": self.MAX_ATTEMPTS,
            }

        except Exception:
            return False, "An error occurred while sending reset code", None

    async def verify_password_reset_otp(self, email: str, otp_code: str) -> Tuple[bool, str, Optional[dict]]:
        try:
            otp_record = await self.prisma.otp_verifications.find_first(
                where={
                    "email": email,
                    "status": OtpStatusEnum.PENDING,
                    "otp_type": OtpTypeEnum.PASSWORD_RESET,
                },
                order={"created_at": "desc"}
            )

            if not otp_record:
                return False, "No pending password reset request found. Please request a new code.", None

            if datetime.now(timezone.utc) > otp_record.expires_at:
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.EXPIRED}
                )
                return False, "Password reset code has expired. Please request a new one.", None

            if otp_record.attempts >= otp_record.max_attempts:
                await self.prisma.otp_verifications.update(
                    where={"id": otp_record.id},
                    data={"status": OtpStatusEnum.FAILED}
                )
                return False, "Maximum attempts exceeded. Please request a new password reset code.", None

            updated_attempts = otp_record.attempts + 1
            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={"attempts": updated_attempts}
                )

            if otp_record.otp_code != otp_code:
                attempts_remaining = otp_record.max_attempts - updated_attempts

                if attempts_remaining <= 0:
                    await self.prisma.otp_verifications.update(
                        where={"id": otp_record.id},
                        data={"status": OtpStatusEnum.FAILED}
                    )
                    return False, "Maximum attempts exceeded. Please request a new password reset code.", None

                return False, f"Invalid code. {attempts_remaining} attempts remaining.", None

            await self.prisma.otp_verifications.update(
                where={"id": otp_record.id},
                data={
                    "status": OtpStatusEnum.VERIFIED,
                    "verified_at": datetime.now(timezone.utc)
                }
            )

            return True, "Password reset code verified", {
                "verified": True,
                "email": email,
            }

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

