import re
import hashlib
import httpx
import time
from passlib.context import CryptContext # type: ignore
from app.core.password_blacklist import is_common_password
from app.core.config import settings

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

class HIBPCircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.timeout = timeout  # seconds
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

USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,30}$")

def normalize_email(e: str) -> str:
    return e.strip()

def validate_username(u: str) -> None:
    if not USERNAME_RE.fullmatch(u):
        raise ValueError("Username must be 3-30 chars: lowercase letters, digits, ., _, -")
    if u.isdigit():
        raise ValueError("Username cannot be only digits")

def validate_password(p: str) -> None:
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

    if settings.hibp_enabled:
        if not hibp_circuit_breaker.should_allow_request():
            return 
        else:
            try:
                sha1 = hashlib.sha1(p.encode("utf-8")).hexdigest().upper()
                prefix, suffix = sha1[:5], sha1[5:]
                url = f"https://api.pwnedpasswords.com/range/{prefix}"
                headers = {"Add-Padding": "true"}
                with httpx.Client(timeout=settings.hibp_timeout_s) as client:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        hibp_circuit_breaker.record_success()
                        for line in resp.text.splitlines():
                            parts = line.split(":")
                            if len(parts) == 2 and parts[0] == suffix:
                                raise ValueError("This password appears in known breaches. Choose a different one.")
                    else:
                        hibp_circuit_breaker.record_failure()
            except (httpx.RequestError, httpx.TimeoutException):
                hibp_circuit_breaker.record_failure()
            except ValueError:
                raise
            except Exception:
                hibp_circuit_breaker.record_failure()

    if re.fullmatch(r"(?i)qwerty[\W_]*\d{0,4}", p):
        raise ValueError("Password is too common or predictable. Please choose a different one.")
    if re.fullmatch(r"(?i)(welcome|password|companyname)[\W_]*\d{0,4}", p):
        raise ValueError("Password is too common or predictable. Please choose a different one.")
    if re.fullmatch(r"(?i)(spring|summer|autumn|fall|winter)[\W_]*20\d{2}[\W_]*", p):
        raise ValueError("Password is too common or predictable. Please choose a different one.")

def hash_password(p: str) -> str:
    return pwd_context.hash(p)
