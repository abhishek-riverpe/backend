import re
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,30}$")  # kept for legacy references (unused)

def normalize_email(e: str) -> str:
    return e.strip()

def validate_username(u: str) -> None:
    if not USERNAME_RE.fullmatch(u):
        raise ValueError("Username must be 3-30 chars: lowercase letters, digits, ., _, -")
    if u.isdigit():
        raise ValueError("Username cannot be only digits")

def validate_password(p: str) -> None:
    # Baseline: length >= 8, and character diversity
    if len(p) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not re.search(r"[A-Z]", p):
        raise ValueError("Password must include at least one uppercase letter")
    if not re.search(r"[a-z]", p):
        raise ValueError("Password must include at least one lowercase letter")
    if not re.search(r"\d", p):
        raise ValueError("Password must include at least one digit")
    if not re.search(r"[^\w\s]", p):
        raise ValueError("Password must include at least one special character")
    # Optional: deny common weak patterns, repeated chars, etc.

def hash_password(p: str) -> str:
    return pwd_context.hash(p)
