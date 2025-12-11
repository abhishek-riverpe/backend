from fastapi import APIRouter, HTTPException, status
from starlette.requests import Request
from .. import schemas
from ..services.captcha_service import captcha_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/captcha",
    tags=["captcha"],
)


@router.post("/generate", response_model=schemas.ApiResponse)
async def generate_captcha(request: Request):
    try:
        session_id = getattr(request.client, "host", None) or "anonymous"
        
        captcha_id, captcha_code, captcha_image = captcha_service.generate_captcha(session_id=session_id)
        
        return {
            "success": True,
            "message": "CAPTCHA generated successfully",
            "data": {
                "captcha_id": captcha_id,
                "captcha_code": captcha_code,  # Keep for debug/fallback
                "captcha_image": f"data:image/png;base64,{captcha_image}",  # Base64 image
                "expires_in_seconds": captcha_service.CAPTCHA_EXPIRY_MINUTES * 60,
            },
            "error": None,
            "meta": {},
        }
    except Exception as e:
        logger.error(f"[CAPTCHA] Error generating CAPTCHA: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate CAPTCHA. Please try again.",
        )


@router.post("/validate", response_model=schemas.ApiResponse)
async def validate_captcha(payload: schemas.CaptchaValidateRequest):
    try:
        is_valid, error_message = captcha_service.validate_captcha(
            captcha_id=payload.captcha_id,
            user_input=payload.captcha_code,
        )
        
        if is_valid:
            return {
                "success": True,
                "message": "CAPTCHA validated successfully",
                "data": {"valid": True},
                "error": None,
                "meta": {},
            }
        else:
            return {
                "success": False,
                "message": error_message,
                "data": {"valid": False},
                "error": {"code": "INVALID_CAPTCHA", "message": error_message},
                "meta": {},
            }
    except Exception as e:
        logger.error(f"[CAPTCHA] Error validating CAPTCHA: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate CAPTCHA. Please try again.",
        )

