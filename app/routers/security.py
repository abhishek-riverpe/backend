import re
import hashlib
import httpx
import time
from passlib.context import CryptContext
from app.core.password_blacklist import is_common_password
from app.core.config import settings


# ============================
# CONSTANTS
# ============================

COMMON_PREDICTABLE_PASSWORD_MSG = (
    "Password is too common or predictable. Please choose a different one."
)

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)


# ============================
# CIRCUIT BREAKER
# ============================

class HIBPCircuitBreaker:
    """Simple circuit breaker for HIBP service to prevent blocking signups when service is down."""
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.last_failure_time = None
        self.is_open = False
    
    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.is_open = True
    
    def record_success(self):
        self.failure_count = 0
        self.is_open = False
    
    def should_allow_request(self):
        if not self.is_open:
            return True
        if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout:
            self.is_open = False
            return True
        return False


hibp_circuit_breaker = HIBPCircuitBreaker()


# ============================
# BASIC STRUCTURE VALIDATION
# ============================

def _validate_basic_structure(p: str) -> None:
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


# ============================
# BLACKLIST VALIDATION
# ============================

def _validate_blacklist(p: str) -> None:
    if is_common_password(p):
        raise ValueError("Password is too common. Please choose a more unique password.")


# ============================
# PREDICTABLE PASSWORD PATTERN VALIDATION
# ============================

def _validate_predictable_patterns(p: str) -> None:
    patterns = [
        r"(?i)qwerty[\W_]*\d{0,4}",
        r"(?i)(welcome|password|companyname)[\W_]*\d{0,4}",
        r"(?i)(spring|summer|autumn|fall|winter)[\W_]*20\d{2}[\W_]*",
    ]
    for pattern in patterns:
        if re.fullmatch(pattern, p):
            raise ValueError(COMMON_PREDICTABLE_PASSWORD_MSG)


# ============================
# HIBP CHECK HELPERS
# ============================

def _hibp_sha1(p: str) -> tuple[str, str]:
    sha1 = hashlib.sha1(p.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def _check_pwned_api(prefix: str, suffix: str) -> bool:
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true"}

    with httpx.Client(timeout=settings.hibp_timeout_s) as client:
        resp = client.get(url, headers=headers)

        if resp.status_code != 200:
            hibp_circuit_breaker.record_failure()
            return False

        hibp_circuit_breaker.record_success()

        for line in resp.text.splitlines():
            line_suffix, _ = line.split(":")
            if line_suffix == suffix:
                return True

    return False


def _validate_hibp(p: str) -> None:
    if not settings.hibp_enabled:
        return

    if not hibp_circuit_breaker.should_allow_request():
        return  # Fail-open

    try:
        prefix, suffix = _hibp_sha1(p)
        if _check_pwned_api(prefix, suffix):
            raise ValueError("This password appears in known breaches. Choose a different one.")

    except (httpx.RequestError, httpx.TimeoutException):
        hibp_circuit_breaker.record_failure()
    except Exception:
        hibp_circuit_breaker.record_failure()


# ============================
# PUBLIC VALIDATION FUNCTION
# ============================

def validate_password(p: str) -> None:
    _validate_basic_structure(p)
    _validate_blacklist(p)
    _validate_hibp(p)
    _validate_predictable_patterns(p)


# ============================
# PASSWORD HASHING
# ============================

def hash_password(p: str) -> str:
    return pwd_context.hash(p)
