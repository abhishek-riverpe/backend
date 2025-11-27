import re
import hashlib
import httpx
import time
from passlib.context import CryptContext
from app.core.password_blacklist import is_common_password
from app.core.config import settings

# LOW-07: Explicitly configure bcrypt rounds for consistent security
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

# LOW-04: Circuit breaker for HIBP service to prevent fail-closed behavior
class HIBPCircuitBreaker:
    """Simple circuit breaker for HIBP service to prevent blocking signups when service is down"""
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.timeout = timeout  # seconds
        self.last_failure_time = None
        self.is_open = False
    
    def record_failure(self):
        """Record a failure and open circuit if threshold reached"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.is_open = True
    
    def record_success(self):
        """Reset failure count on success"""
        self.failure_count = 0
        self.is_open = False
    
    def should_allow_request(self):
        """Check if circuit is closed or timeout has passed"""
        if not self.is_open:
            return True
        # Check if timeout has passed
        if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout:
            # Half-open: allow one request to test if service is back
            self.is_open = False
            return True
        return False

# Global circuit breaker instance
hibp_circuit_breaker = HIBPCircuitBreaker()

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
    # LOW-04: Circuit breaker prevents fail-closed behavior when HIBP is down
    if settings.hibp_enabled:
        # Check circuit breaker - if open, skip HIBP check to allow signups
        if not hibp_circuit_breaker.should_allow_request():
            # Circuit is open - skip HIBP check to prevent blocking legitimate signups
            # This is acceptable as we still have other password validation (common passwords, patterns)
            pass
        else:
            try:
                sha1 = hashlib.sha1(p.encode("utf-8")).hexdigest().upper()
                prefix, suffix = sha1[:5], sha1[5:]
                url = f"https://api.pwnedpasswords.com/range/{prefix}"
                headers = {"Add-Padding": "true"}  # reduce timing correlation
                with httpx.Client(timeout=settings.hibp_timeout_s) as client:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        # Record success
                        hibp_circuit_breaker.record_success()
                        # Each line: HASH_SUFFIX:COUNT
                        for line in resp.text.splitlines():
                            parts = line.split(":")
                            if len(parts) == 2 and parts[0] == suffix:
                                raise ValueError("This password appears in known breaches. Choose a different one.")
                    else:
                        # Non-200 response - record failure but don't block user
                        hibp_circuit_breaker.record_failure()
            except (httpx.RequestError, httpx.TimeoutException) as e:
                # Network/timeout errors - record failure but don't block user
                # LOW-04: Fail-open behavior when HIBP is unavailable
                hibp_circuit_breaker.record_failure()
                # Allow signup to proceed - other validations still apply
            except ValueError:
                # Password is breached - re-raise to block signup
                raise
            except Exception:
                # Other unexpected errors - record failure but don't block user
                hibp_circuit_breaker.record_failure()
                # Allow signup to proceed - other validations still apply

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
