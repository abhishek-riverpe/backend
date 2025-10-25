from pydantic import BaseModel, EmailStr, Field
from typing import Optional
class SignInInput(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)
    
class UserCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)

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
