import logging
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


def upstream_error(
    log_message: str,
    *,
    user_message: str = "Upstream service is currently unavailable. Please try again later.",
    status_code: int = status.HTTP_502_BAD_GATEWAY,
) -> HTTPException:
    """
    Log detailed upstream error server-side and return a generic HTTPException for clients.

    This helper is used to fix MED-02 (Information disclosure via error messages) by ensuring
    we never leak upstream response bodies or internal details to callers, while still
    preserving useful diagnostics in server logs.
    """
    logger.error(log_message, exc_info=True)
    return HTTPException(status_code=status_code, detail=user_message)


def internal_error(
    log_message: str,
    *,
    user_message: str = "Internal server error. Please try again later.",
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
) -> HTTPException:
    """
    Log detailed internal error server-side and return a generic HTTPException.
    """
    logger.error(log_message, exc_info=True)
    return HTTPException(status_code=status_code, detail=user_message)


