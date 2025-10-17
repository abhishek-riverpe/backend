from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class UserCreate(BaseModel):
    username: EmailStr
    password: str = Field(..., min_length=6)
    firstName: str
    lastName: str

class UserLogin(BaseModel):
    username: EmailStr
    password: str

class UserUpdate(BaseModel):
    password: Optional[str] = Field(None, min_length=6)
    firstName: Optional[str] = None
    lastName: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class TransferRequest(BaseModel):
    to: str # user id
    amount: float = Field(..., gt=0)
