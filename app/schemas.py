from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any, Dict
class SignInInput(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)
    
class UserCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

class UserLogin(BaseModel):
    username: EmailStr
    password: str

class UserUpdate(BaseModel):
    password: Optional[str] = Field(None, min_length=6)
    firstName: Optional[str] = None
    lastName: Optional[str] = None

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    sub: Optional[str] = None  # user id
    type: Optional[str] = None # access or refresh

class RefreshRequest(BaseModel):
    refresh_token: str

class TransferRequest(BaseModel):
    to: str # user id
    amount: float = Field(..., gt=0)


# -----------------------------
# Unified API response schemas
# -----------------------------

class UserOut(BaseModel):
    entity_id: Optional[str] = None
    external_entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    email_verified: Optional[bool] = None
    last_login_at: Optional[str] = None
    login_attempts: Optional[int] = None
    locked_until: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class AuthData(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut

class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    meta: Optional[Dict[str, Any]] = None

class AuthResponse(ApiResponse):
    data: AuthData
