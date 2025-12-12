from fastapi import HTTPException, status


def upstream_error(
    log_message: str,
    *,
    user_message: str = "Upstream service is currently unavailable. Please try again later.",
    status_code: int = status.HTTP_502_BAD_GATEWAY,
) -> HTTPException:
    return HTTPException(status_code=status_code, detail=user_message)


def internal_error(
    log_message: str,
    *,
    user_message: str = "Internal server error. Please try again later.",
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
) -> HTTPException:
    return HTTPException(status_code=status_code, detail=user_message)


