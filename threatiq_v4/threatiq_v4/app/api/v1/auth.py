"""
Auth endpoints: login, token refresh, API key management.
"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from app.core.security import (
    create_access_token, verify_password, hash_password,
    audit_log, default_limiter, rate_limit
)

router = APIRouter()

# In-memory user store for dev (production: DB User table)
_USERS: dict = {
    "admin": {
        "user_id": "admin",
        "hashed_password": hash_password("ThreatIQ@Admin25!"),
        "role": "admin",
        "tenant_id": "default",
        "max_tlp": "TLP:RED",
    },
    "analyst": {
        "user_id": "analyst",
        "hashed_password": hash_password("ThreatIQ@Analyst25!"),
        "role": "analyst",
        "tenant_id": "default",
        "max_tlp": "TLP:AMBER",
    },
    "viewer": {
        "user_id": "viewer",
        "hashed_password": hash_password("ThreatIQ@Viewer25!"),
        "role": "viewer",
        "tenant_id": "default",
        "max_tlp": "TLP:GREEN",
    },
}


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if len(v) < 3 or len(v) > 64:
            raise ValueError("Username must be 3-64 characters")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8 or len(v) > 128:
            raise ValueError("Password must be 8-128 characters")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    tenant_id: str


@router.post("/login", response_model=TokenResponse, tags=["Auth"],
             summary="Login and receive JWT")
async def login(request: Request, body: LoginRequest,
                _rl=Depends(rate_limit(default_limiter))):
    """
    Returns a JWT on success. Intentionally generic error message
    to prevent username enumeration (security best practice).
    """
    user = _USERS.get(body.username)
    # Constant-time comparison prevents timing attacks
    if not user or not verify_password(body.password, user["hashed_password"]):
        audit_log.log("unknown", "default", "login_failed",
                      "auth", details={"username": body.username})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = create_access_token(
        user_id=user["user_id"],
        tenant_id=user["tenant_id"],
        role=user["role"],
        max_tlp=user["max_tlp"],
    )
    audit_log.log(user["user_id"], user["tenant_id"], "login_success", "auth")
    from app.core.config import settings
    return TokenResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=user["role"],
        tenant_id=user["tenant_id"],
    )


@router.get("/me", tags=["Auth"], summary="Get current user info")
async def me(request: Request, _rl=Depends(rate_limit(default_limiter))):
    """Returns the currently authenticated user profile."""
    from app.core.security import get_current_user
    from fastapi import Depends
    auth = request.headers.get("authorization","")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    from app.core.security import _decode_token
    payload = _decode_token(auth.split(" ",1)[1])
    return {"user_id": payload.sub, "role": payload.role,
            "tenant_id": payload.tenant_id, "max_tlp": payload.max_tlp}
