import re
import hashlib
import httpx
from passlib.context import CryptContext
from app.core.password_blacklist import is_common_password
from app.core.config import settings

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

    if is_common_password(p):
        raise ValueError("Password is too common. Please choose a more unique password.")

    # Optional: Check against breached passwords (Have I Been Pwned - k-anonymity)
    if settings.hibp_enabled:
        try:
            sha1 = hashlib.sha1(p.encode("utf-8")).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {"Add-Padding": "true"}  # reduce timing correlation
            with httpx.Client(timeout=settings.hibp_timeout_s) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    # Each line: HASH_SUFFIX:COUNT
                    for line in resp.text.splitlines():
                        parts = line.split(":")
                        if len(parts) == 2 and parts[0] == suffix:
                            raise ValueError("This password appears in known breaches. Choose a different one.")
                # Ignore non-200 silently to avoid blocking users if HIBP is down
        except Exception:
            # Fail-closed when HIBP is enabled: block if the breach check cannot be performed
            raise ValueError("Unable to validate password against breach database. Please try again or choose a different password.")

    # Pattern-based rejects for popular-but-compliant passwords
    # 1) QWERTY + optional separators + up to 4 digits (e.g., Qwerty@123)
    if re.fullmatch(r"(?i)qwerty[\W_]*\d{0,4}", p):
        raise ValueError("Password is too common or predictable. Please choose a different one.")
    # 2) Welcome/Password/CompanyName + optional separators + up to 4 digits (e.g., Welcome@123)
    if re.fullmatch(r"(?i)(welcome|password|companyname)[\W_]*\d{0,4}", p):
        raise ValueError("Password is too common or predictable. Please choose a different one.")
    # 3) Season + year (e.g., Summer2025!, Winter2024)
    if re.fullmatch(r"(?i)(spring|summer|autumn|fall|winter)[\W_]*20\d{2}[\W_]*", p):
        raise ValueError("Password is too common or predictable. Please choose a different one.")

def hash_password(p: str) -> str:
    return pwd_context.hash(p)
