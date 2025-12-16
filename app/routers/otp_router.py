from fastapi import APIRouter, HTTPException, status
from app.schemas.otp import (
    OtpSendRequest,
    OtpVerifyRequest,
    OtpSendResponse,
    OtpVerifyResponse,
    EmailOtpSendRequest,
    EmailOtpVerifyRequest,
)
from app.services.otp_service import OTPService
from app.core.database import prisma

router = APIRouter(prefix="/api/v1/otp", tags=["OTP"])


@router.post("/send", response_model=OtpSendResponse)
async def send_otp(request: OtpSendRequest):
    try:
        otp_service = OTPService(prisma)
        success, message, data = await otp_service.send_otp(
            phone_number=request.phone_number,
            country_code=request.country_code
        )
        
        if not success:
            return OtpSendResponse(
                success=False,
                message=message,
                data=None,
                meta={"error_type": "rate_limit" if "wait" in message.lower() else "send_failed"}
            )
        
        return OtpSendResponse(
            success=True,
            message=message,
            data=data,
            meta={"phone_number": f"{request.country_code}{request.phone_number}"}
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP. Please try again later."
        )


@router.post("/verify", response_model=OtpVerifyResponse)
async def verify_otp(request: OtpVerifyRequest):
    try:
        otp_service = OTPService(prisma)
        success, message, data = await otp_service.verify_otp(
            phone_number=request.phone_number,
            country_code=request.country_code,
            otp_code=request.otp_code
        )
        
        if not success:
            return OtpVerifyResponse(
                success=False,
                message=message,
                data=None,
                meta={
                    "error_type": "invalid_otp" if "invalid" in message.lower() else "expired_otp",
                    "phone_number": f"{request.country_code}{request.phone_number}"
                }
            )
        
        return OtpVerifyResponse(
            success=True,
            message=message,
            data=data,
            meta={"phone_number": f"{request.country_code}{request.phone_number}"}
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify OTP. Please try again later."
        )


@router.post("/email/send", response_model=OtpSendResponse)
async def send_email_otp(request: EmailOtpSendRequest):
    try:
        otp_service = OTPService(prisma)
        success, message, data = await otp_service.send_email_otp(email=request.email)
        
        if not success:
            return OtpSendResponse(
                success=False,
                message=message,
                data=None,
                meta={"error_type": "rate_limit" if "wait" in message.lower() else "send_failed"}
            )
        
        return OtpSendResponse(
            success=True,
            message=message,
            data=data,
            meta={"email": request.email}
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP. Please try again later."
        )


@router.post("/email/verify", response_model=OtpVerifyResponse)
async def verify_email_otp(request: EmailOtpVerifyRequest):
    try:
        otp_service = OTPService(prisma)
        success, message, data = await otp_service.verify_email_otp(
            email=request.email,
            otp_code=request.otp_code
        )
        
        if not success:
            return OtpVerifyResponse(
                success=False,
                message=message,
                data=None,
                meta={
                    "error_type": "invalid_otp" if "invalid" in message.lower() else "expired_otp",
                    "email": request.email
                }
            )
        
        return OtpVerifyResponse(
            success=True,
            message=message,
            data=data,
            meta={"email": request.email}
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify OTP. Please try again later."
        )

