def sanitize_for_log(message: str) -> str:
    return message.replace("\n", "\\n").replace("\r", "\\r") if isinstance(message, str) else str(message)