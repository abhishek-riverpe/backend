import logging
from fastapi import HTTPException, status
from .log_sanitizer import sanitize_for_log 
logger = logging.getLogger(__name__)


def upstream_error(
    log_message: str,
    *,
    user_message: str = "Upstream service is currently unavailable. Please try again later.",
    status_code: int = status.HTTP_502_BAD_GATEWAY,
) -> HTTPException:
    safe_message = sanitize_for_log(log_message)
    logger.error(safe_message, exc_info=True)
    return HTTPException(status_code=status_code, detail=user_message)


def internal_error(
    log_message: str,
    *,
    user_message: str = "Internal server error. Please try again later.",
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
) -> HTTPException:
    safe_message = sanitize_for_log(log_message)
    logger.error(safe_message, exc_info=True)
    return HTTPException(status_code=status_code, detail=user_message)


