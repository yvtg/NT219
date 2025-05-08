
from datetime import datetime
from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    HoTen: str
    Email: EmailStr
    Password: str
    role: Optional[str] = "user"
    plan: str
class UserResponse(BaseModel):
    HoTen: str
    Email: str
    role: str
    
class Config:
    orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class UserInfo(BaseModel):
    username: str
    email: str
    role: str
class RefreshRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # Durée de validité en secondes