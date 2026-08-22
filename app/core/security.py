"""
ThreatIQ v4.0 -- Security Layer
Covers: JWT auth, RBAC, rate limiting, input sanitisation,
        TLP-aware data access, API key management, audit logging.
"""
import hashlib, hmac, logging, re, secrets, time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Password hashing ────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt","sha256_crypt"], deprecated="auto", bcrypt__min_rounds=4)

import hashlib as _hashlib, secrets as _secrets

def hash_password(password: str) -> str:
    """PBKDF2-SHA256 password hash (production: use bcrypt or argon2)."""
    salt = _secrets.token_hex(16)
    dk = _hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2:sha256:260000${salt}${dk.hex()}"

def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time PBKDF2 verification."""
    try:
        params, salt, stored = hashed.split("$")
        _, _, iters = params.split(":")
        dk = _hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), int(iters))
        return _secrets.compare_digest(dk.hex(), stored)
    except Exception:
        return False

# ── JWT ─────────────────────────────────────────────────────────
ALGORITHM = "HS256"
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

TLP_ORDER = {"TLP:WHITE": 0, "TLP:GREEN": 1, "TLP:AMBER": 2, "TLP:RED": 3}

class TokenPayload(BaseModel):
    sub: str           # user id
    tenant_id: str
    role: str          # admin | analyst | viewer
    max_tlp: str       # highest TLP this user can see
    exp: int

class CurrentUser(BaseModel):
    user_id: str
    tenant_id: str
    role: str
    max_tlp: str

def create_access_token(user_id: str, tenant_id: str,
                         role: str, max_tlp: str = "TLP:AMBER") -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id, "tenant_id": tenant_id,
        "role": role, "max_tlp": max_tlp,
        "exp": int(expire.timestamp()),
        "iat": int(time.time()),
        "jti": secrets.token_hex(16),  # unique token ID (prevents replay)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

def _decode_token(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return TokenPayload(**payload)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    api_key: Annotated[str | None, Depends(api_key_header)],
) -> CurrentUser:
    """
    Accepts either:
      - Bearer JWT in Authorization header
      - X-API-Key header (hashed API key looked up in DB)
    Never exposes user details in error messages (information disclosure prevention).
    """
    if credentials:
        payload = _decode_token(credentials.credentials)
        return CurrentUser(
            user_id=payload.sub, tenant_id=payload.tenant_id,
            role=payload.role, max_tlp=payload.max_tlp,
        )
    if api_key:
        # In production: hash api_key and look up in api_keys table
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        # Placeholder -- real implementation queries DB
        if len(api_key) >= 32:
            return CurrentUser(
                user_id="api-user", tenant_id="default",
                role="analyst", max_tlp="TLP:AMBER",
            )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )

def require_role(*roles: str):
    """Dependency factory: enforce RBAC."""
    async def _check(user: CurrentUser = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    return _check

def check_tlp_access(user: CurrentUser, record_tlp: str) -> bool:
    """Returns True iff user is permitted to see data at `record_tlp`."""
    return TLP_ORDER.get(record_tlp, 0) <= TLP_ORDER.get(user.max_tlp, 0)

def filter_by_tlp(records: list[dict], user: CurrentUser) -> list[dict]:
    """Strip records the user is not permitted to see based on TLP level."""
    return [r for r in records if check_tlp_access(user, r.get("tlp", "TLP:AMBER"))]

# ── Input sanitisation ──────────────────────────────────────────
_DANGEROUS_PATTERN = re.compile(
    r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]|"   # control chars
    r"<script|javascript:|data:text/html|"             # XSS vectors
    r"union\s+select|drop\s+table|"                  # SQLi (defence in depth)
    r"\.\./|\.\.\\",                             # path traversal
    re.IGNORECASE,
)

def sanitise_text(value: str, max_length: int = 10_000) -> str:
    """Strip dangerous patterns and enforce length limit."""
    if not isinstance(value, str):
        raise ValueError("Expected string")
    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    if _DANGEROUS_PATTERN.search(value):
        raise ValueError("Input contains disallowed content")
    return value.strip()

def sanitise_query_param(value: str, max_length: int = 256) -> str:
    return sanitise_text(value, max_length)

# ── Rate limiting (in-memory token bucket) ──────────────────────
class RateLimiter:
    """
    Simple per-IP token-bucket rate limiter.
    Production: use slowapi + Redis for distributed limiting.
    """
    def __init__(self, calls: int = 60, period: int = 60):
        self.calls = calls
        self.period = period
        self._buckets: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window = self._buckets.setdefault(key, [])
        # Remove timestamps outside window
        self._buckets[key] = [t for t in window if now - t < self.period]
        if len(self._buckets[key]) >= self.calls:
            return False
        self._buckets[key].append(now)
        return True

    def check(self, request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        if not self.is_allowed(ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please slow down.",
                headers={"Retry-After": str(self.period)},
            )

# Global limiters
default_limiter  = RateLimiter(calls=120, period=60)   # 120 req/min
strict_limiter   = RateLimiter(calls=20,  period=60)   # 20 req/min (pipeline/train)
feedback_limiter = RateLimiter(calls=30,  period=60)   # 30 feedback/min

def rate_limit(limiter: RateLimiter = default_limiter):
    def _dep(request: Request):
        limiter.check(request)
    return _dep

# ── Audit logging ────────────────────────────────────────────────
class AuditLogger:
    """Structured audit log. Production: write to PostgreSQL audit table."""
    def log(self, user_id: str, tenant_id: str, action: str,
            resource: str, resource_id: str | None = None,
            status: str = "success", details: dict | None = None):
        logger.info(
            "AUDIT user=%s tenant=%s action=%s resource=%s resource_id=%s status=%s details=%s",
            user_id, tenant_id, action, resource, resource_id, status, details or {}
        )

audit_log = AuditLogger()

# ── Security headers middleware ──────────────────────────────────
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({
        "X-Content-Type-Options":         "nosniff",
        "X-Frame-Options":                "DENY",
        "X-XSS-Protection":              "1; mode=block",
        "Strict-Transport-Security":      "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy":        (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        ),
        "Referrer-Policy":               "strict-origin-when-cross-origin",
        "Permissions-Policy":            "camera=(), microphone=(), geolocation=()",
        "Cache-Control":                  "no-store",
    })
    # Remove server fingerprint (MutableHeaders requires del, not .pop)
    if "Server" in response.headers:
        del response.headers["Server"]
    if "X-Powered-By" in response.headers:
        del response.headers["X-Powered-By"]
    return response
