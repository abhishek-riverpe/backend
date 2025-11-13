"""
OTP Router

Handles OTP sending and verification endpoints for phone number validation.
"""

import logging
from fastapi import APIRouter, HTTPException, status
from app.schemas.otp import (
    OtpSendRequest,
    OtpVerifyRequest,
    OtpSendResponse,
    OtpVerifyResponse,
)
from app.services.otp_service import OTPService
from app.core.database import prisma

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/otp", tags=["OTP"])


@router.post("/send", response_model=OtpSendResponse)
async def send_otp(request: OtpSendRequest):
    """
    Send OTP to phone number
    
    - **phone_number**: Phone number without country code
    - **country_code**: Country code (e.g., +1, +91)
    
    Returns:
    - Success message with OTP session details
    - Rate limit information
    """
    try:
        logger.info(f"[OTP] Send OTP request for {request.country_code}{request.phone_number}")
        
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
        logger.warning(f"[OTP] Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"[OTP] Send OTP error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP. Please try again later."
        )


@router.post("/verify", response_model=OtpVerifyResponse)
async def verify_otp(request: OtpVerifyRequest):
    """
    Verify OTP code
    
    - **phone_number**: Phone number without country code
    - **country_code**: Country code (e.g., +1, +91)
    - **otp_code**: 6-digit OTP code
    
    Returns:
    - Verification success status
    - Remaining attempts if failed
    """
    try:
        logger.info(f"[OTP] Verify OTP request for {request.country_code}{request.phone_number}")
        
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
        logger.warning(f"[OTP] Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"[OTP] Verify OTP error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify OTP. Please try again later."
        )


@router.post("/resend", response_model=OtpSendResponse)
async def resend_otp(request: OtpSendRequest):
    """
    Resend OTP to phone number (same as /send but more explicit)
    
    - **phone_number**: Phone number without country code
    - **country_code**: Country code (e.g., +1, +91)
    
    Returns:
    - Success message with new OTP session details
    """
    # Resend is the same as send - just invalidates old OTP and sends new one
    return await send_otp(request)

